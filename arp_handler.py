# ==============================================
# 4. LAYER 2 (ARP) HANDLING
# ==============================================
def handle_arp_request(arp_packet, packet_in, event, dpid):
    """Handles ARP Requests (using Proxy ARP)"""
    target_ip = str(arp_packet.protodst)
    source_ip = str(arp_packet.protosrc)
    source_mac = arp_packet.hwsrc
    
    # Learn the location (L2/L3) of the sending host
    learn_location(source_ip, dpid, packet_in.in_port)
    arp_cache[source_ip] = source_mac
    
    # Check if it's an ARP for one of the router's gateways
    if target_ip in router_interfaces:
        log.info("ARP Request for router interface %s" % target_ip)
        reply_mac = router_interfaces[target_ip]
    else:
        # If not, the controller will reply on behalf (Proxy ARP)
        target_gateway = find_gateway_for_ip(target_ip)
        if target_gateway:
            log.info("Proxy ARP: Replying for %s with gateway %s MAC" % (target_ip, target_gateway))
            reply_mac = router_interfaces[target_gateway]
        else:
            log.debug("ARP Request for unknown network %s, ignoring" % target_ip)
            return
    
    # Create ARP Reply packet
    arp_reply = arp()
    arp_reply.hwsrc = reply_mac
    arp_reply.hwdst = source_mac
    arp_reply.opcode = arp.REPLY
    arp_reply.protosrc = IPAddr(target_ip)
    arp_reply.protodst = IPAddr(source_ip)
    
    ether = ethernet(type=ethernet.ARP_TYPE, src=reply_mac, dst=source_mac)
    ether.payload = arp_reply
    
    # Send the reply packet out the same port it came in on
    msg = of.ofp_packet_out()
    msg.data = ether.pack()
    msg.actions.append(of.ofp_action_output(port=packet_in.in_port))
    event.connection.send(msg)
    
    log.info("Sent ARP Reply: %s is at %s" % (target_ip, reply_mac))

def handle_arp_reply(arp_packet, packet_in, event, dpid):
    """Handles ARP Replies"""
    source_ip = str(arp_packet.protosrc)
    source_mac = arp_packet.hwsrc
    
    # Update caches
    arp_cache[source_ip] = source_mac
    learn_location(source_ip, dpid, packet_in.in_port)
    
    log.info("ARP Cache updated: %s -> %s" % (source_ip, source_mac))
    
    # Process any queued packets waiting for this ARP reply
    if source_ip in packet_queue:
        log.info("Processing queued packets for %s" % source_ip)
        queued_items = packet_queue[source_ip]
        del packet_queue[source_ip] 
        
        for queued_data in queued_items:
            log.debug("Processing queued packet for %s" % source_ip)
            q_event = queued_data['event']
            q_packet_in = queued_data['packet_in']
            q_packet = q_event.parsed
            q_ip_packet = q_packet.payload
            
            # Re-call the IP handler, which will now succeed
            handle_ip_packet(q_ip_packet, q_packet, q_packet_in, q_event)

def send_arp_request(target_ip):
    """Sends a broadcast ARP request to find the MAC of a target IP (for inter-subnet)"""
    gateway = find_gateway_for_ip(target_ip)
    if not gateway:
        log.warning("No gateway found to send ARP request for %s" % target_ip)
        return
    
    arp_req = arp()
    arp_req.hwsrc = router_interfaces[gateway]
    arp_req.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
    arp_req.opcode = arp.REQUEST
    arp_req.protosrc = IPAddr(gateway)
    arp_req.protodst = IPAddr(target_ip)
    
    ether = ethernet(type=ethernet.ARP_TYPE, 
                     src=router_interfaces[gateway], 
                     dst=EthAddr("ff:ff:ff:ff:ff:ff"))
    ether.payload = arp_req
    
    # Broadcast on ALL connected switches
    msg = of.ofp_packet_out()
    msg.data = ether.pack()
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    
    log.info("Broadcasting ARP Request for %s on all switches" % target_ip)
    for dpid, conn in connections.items():
        conn.send(msg)

def send_gratuitous_arp(dst_ip, src_ip):
    """Sends a 'fake' (gratuitous) ARP to inform a host of the router's MAC"""
    if dst_ip not in ip_to_location:
        log.debug("Cannot send gratuitous ARP: unknown location for %s" % dst_ip)
        return
        
    if dst_ip not in arp_cache:
        log.debug("Cannot send gratuitous ARP: unknown MAC for %s" % dst_ip)
        return
        
    (dst_dpid, dst_port) = ip_to_location[dst_ip]
    dst_mac = arp_cache.get(dst_ip, EthAddr("ff:ff:ff:ff:ff:ff"))
    
    src_gateway = find_gateway_for_ip(src_ip)
    if not src_gateway:
        return
    
    # Create ARP reply: "src_ip is at gateway_mac"
    arp_reply = arp()
    arp_reply.hwsrc = router_interfaces[src_gateway]
    arp_reply.hwdst = dst_mac
    arp_reply.opcode = arp.REPLY
    arp_reply.protosrc = IPAddr(src_ip)
    arp_reply.protodst = IPAddr(dst_ip)
    
    ether = ethernet(type=ethernet.ARP_TYPE, 
                     src=router_interfaces[src_gateway], 
                     dst=dst_mac)
    ether.payload = arp_reply
    
    # Send the packet to the correct (switch, port) of the destination host
    msg = of.ofp_packet_out()
    msg.data = ether.pack()
    msg.actions.append(of.ofp_action_output(port=dst_port))
    
    if dst_dpid not in connections:
        log.warning("Cannot send gratuitous ARP: switch %s not connected" % dst_dpid)
        return
        
    connections[dst_dpid].send(msg)
    log.debug("Sent gratuitous ARP to %s (on %s:%s): %s is at %s" % (dst_ip, dst_dpid, dst_port, src_ip, router_interfaces[src_gateway]))

