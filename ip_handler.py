
# ==============================================
# 5. LAYER 3 (IP & ICMP) HANDLING
# ==============================================

def handle_ip_packet(ip_packet, packet, packet_in, event):
    """
    Handles an IP packet.
    This function is only called if the packet does NOT match a high-priority L4 ACL rule.
    """
    src_ip = str(ip_packet.srcip)
    dst_ip = str(ip_packet.dstip)
    
    log.debug("IP packet from %s: %s -> %s" % (poxutil.dpid_to_str(event.dpid), src_ip, dst_ip))
    
    # Learn the source host's location
    learn_location(src_ip, event.dpid, packet_in.in_port)
    
    # 1. Is the packet destined for the Router itself?
    if dst_ip in router_interfaces:
        # If it's an ICMP (ping router), send a reply
        if ip_packet.protocol == IP_ICMP_PROTOCOL:
            icmp_packet = ip_packet.payload
            if icmp_packet.type == ICMP_ECHO_REQUEST:
                log.info("ICMP Echo Request to router %s" % dst_ip)
                send_icmp_reply(ip_packet, packet, packet_in, event)
                return
        log.debug("Packet to router interface, ignoring")
        return
    
    # 2. Make routing decision
    src_gateway = find_gateway_for_ip(src_ip)
    dst_gateway = find_gateway_for_ip(dst_ip)
    
    if src_gateway == dst_gateway:
        # SAME SUBNET (e.g., h1 -> h2)
        log.debug("Same subnet routing: %s -> %s" % (src_ip, dst_ip))
        switch_packet(packet_in, event, dst_ip, src_ip)
    else:
        # DIFFERENT SUBNET (e.g., h1 -> h5)
        log.debug("Inter-subnet routing: %s -> %s" % (src_ip, dst_ip))
        route_packet(ip_packet, packet, packet_in, event, dst_ip)

def switch_packet(packet_in, event, dst_ip, src_ip):
    """Handles packets within the same subnet (INTRA-SWITCH)"""
    
    # Do we know the MAC and location of the destination host?
    if dst_ip in ip_to_location and dst_ip in arp_cache:
        (dst_dpid, out_port) = ip_to_location[dst_ip]
        dst_mac = arp_cache[dst_ip]
        
        # Sanity check: intra-subnet packet should be on the same switch
        if event.dpid != dst_dpid:
            log.error("Intra-subnet packet destined for different switch? %s (%s) -> %s (%s)" %
                      (src_ip, event.dpid, dst_ip, dst_dpid))
            route_packet(event.parsed.payload, event.parsed, packet_in, event, dst_ip)
            return

        dst_gateway = find_gateway_for_ip(dst_ip)
        src_mac = router_interfaces[dst_gateway]
        
        # Send PacketOut
        msg = of.ofp_packet_out()
        msg.data = packet_in.data
        msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)
        
        log.debug("Switched packet (intra-switch) to port %d" % out_port)
        
        # Install flow rule
        install_route_flow(event, dst_ip, dst_mac, src_mac, out_port)
        
        if src_ip in arp_cache:
            send_gratuitous_arp(dst_ip, src_ip)
    else:
        # If unknown, send ARP and queue the packet
        log.info("MAC/port unknown for same-subnet host %s, queuing" % dst_ip)
        if dst_ip not in packet_queue:
            packet_queue[dst_ip] = []
            send_arp_request(dst_ip)
        packet_queue[dst_ip].append({
            'packet_in': packet_in,
            'event': event,
            'dst_ip': dst_ip
        })

def route_packet(ip_packet, packet, packet_in, event, dst_ip):
    """Initiates inter-subnet routing (INTER-SWITCH)"""
    dst_gateway = find_gateway_for_ip(dst_ip)
    
    if not dst_gateway:
        # Destination network not found -> Send ICMP Unreachable
        log.info("Network unreachable for %s" % dst_ip)
        send_icmp_unreachable(ip_packet, packet, packet_in, event)
        return
    
    # Do we know the MAC and location of the destination host?
    if dst_ip in arp_cache and dst_ip in ip_to_location:
        # Yes -> forward the packet
        forward_ip_packet(packet_in, event, dst_ip)
    else:
        # No -> Send ARP and queue the packet
        log.info("MAC/location unknown for %s, queuing packet and sending ARP" % dst_ip)
        if dst_ip not in packet_queue:
            packet_queue[dst_ip] = []
            send_arp_request(dst_ip)
        packet_queue[dst_ip].append({
            'packet_in': packet_in,
            'event': event,
            'dst_ip': dst_ip
        })

def forward_ip_packet(packet_in, event, dst_ip):
    """
    Forwards an L3 packet (with MAC rewrite) to the destination host.
    *** THIS FUNCTION CONTAINS THE ACL FIX ***
    """
    if dst_ip not in arp_cache:
        log.error("Cannot forward: no MAC for %s" % dst_ip)
        return
    
    if dst_ip not in ip_to_location:
        log.error("Cannot forward: no location for %s" % dst_ip)
        return
    
    parsed = event.parsed
    ip_pkt = parsed.payload
    src_ip = str(ip_pkt.srcip)
    
    # Get destination host info
    dst_mac = arp_cache[dst_ip]
    (dst_dpid, out_port) = ip_to_location[dst_ip] # (dst_dpid = s2, out_port = h5's port)
    
    # Get router's gateway MAC
    dst_gateway = find_gateway_for_ip(dst_ip)
    src_mac = router_interfaces[dst_gateway]     # (MAC of router interface 10.0.2.1)
    
    # ==============================================
    # === ACL LOGIC FIX IS HERE ===
    # ==============================================

    # 1. Send PacketOut BACK to the SOURCE switch (s1)
    #    This packet will be FLOODED, traverse the inter-switch link, and
    #    BE PROCESSED BY THE FLOW TABLE OF s2.
    msg_po = of.ofp_packet_out()
    msg_po.data = packet_in.data # Original packet data (h3 -> router_mac_s1)
    
    # Rewrite MAC (L3 Routing)
    msg_po.actions.append(of.ofp_action_dl_addr.set_src(src_mac)) # New source MAC
    msg_po.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac)) # New destination MAC
    
    # Instruct the SOURCE switch (s1) to FLOOD this rewritten packet
    msg_po.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    
    # Send this command back to the SOURCE switch (s1, the one that sent the PacketIn)
    event.connection.send(msg_po)

    log.info("Forwarded packet (PO via FLOOD on s1) to %s (MAC: %s) via switch %s" % 
             (dst_ip, dst_mac, poxutil.dpid_to_str(event.dpid)))

    # 2. Install flow rule on the SOURCE switch (s1)
    #    This part remains the same; it's correct for subsequent packets.
    install_route_flow(event, dst_ip, dst_mac, src_mac, of.OFPP_FLOOD)
    
    if src_ip in arp_cache:
        send_gratuitous_arp(dst_ip, src_ip)


def send_icmp_reply(ip_packet, packet, packet_in, event):
    """Sends an ICMP Echo Reply (ping reply)"""
    icmp_request = ip_packet.payload
    
    # Create ICMP Reply
    icmp_reply = icmp()
    icmp_reply.type = ICMP_ECHO_REPLY
    icmp_reply.code = 0
    icmp_reply.payload = icmp_request.payload
    
    # Create IP packet
    ip_reply = ipv4()
    ip_reply.protocol = IP_ICMP_PROTOCOL
    ip_reply.srcip = ip_packet.dstip # Swap
    ip_reply.dstip = ip_packet.srcip # Swap
    ip_reply.payload = icmp_reply
    
    # Create Ethernet frame
    ether = ethernet(type=ethernet.IP_TYPE, src=packet.dst, dst=packet.src)
    ether.payload = ip_reply
    
    # Send it
    msg = of.ofp_packet_out()
    msg.data = ether.pack()
    msg.actions.append(of.ofp_action_output(port=packet_in.in_port))
    event.connection.send(msg)
    
    log.info("Sent ICMP Echo Reply to %s" % ip_packet.srcip)

def send_icmp_unreachable(ip_packet, packet, packet_in, event):
    """Sends an ICMP Network Unreachable"""
    icmp_unreach = icmp()
    icmp_unreach.type = ICMP_DEST_UNREACH
    icmp_unreach.code = ICMP_CODE_NET_UNREACH
    
    orig_ip = ip_packet.pack()[:28] # Original IP header + 8 bytes data
    icmp_unreach.payload = orig_ip
    
    src_gateway = find_gateway_for_ip(str(ip_packet.srcip))
    
    ip_reply = ipv4()
    ip_reply.protocol = IP_ICMP_PROTOCOL
    ip_reply.srcip = IPAddr(src_gateway) if src_gateway else ip_packet.dstip
    ip_reply.dstip = ip_packet.srcip
    ip_reply.payload = icmp_unreach
    
    router_mac = router_interfaces.get(src_gateway) if src_gateway else packet.dst
    
    ether = ethernet(type=ethernet.IP_TYPE, src=router_mac, dst=packet.src)
    ether.payload = ip_reply
    
    msg = of.ofp_packet_out()
    msg.data = ether.pack()
    msg.actions.append(of.ofp_action_output(port=packet_in.in_port))
    event.connection.send(msg)
    
    log.info("Sent ICMP Network Unreachable to %s" % ip_packet.srcip)
