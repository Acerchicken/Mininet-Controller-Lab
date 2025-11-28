# =============================================================================
# 1. YÊU CẦU 1: ARP HANDLER (arp_handler.py)
# =============================================================================

def send_arp_request_smart(target_ip):
    """Gửi ARP Request unicast đến switch đích (Tránh Flood)"""
    gw = find_gateway_for_ip(target_ip)
    if not gw: return
    target_dpid = gateway_ip_to_dpid.get(gw)
    if not target_dpid or target_dpid not in connections: return

    src_mac = router_interfaces[gw]
    r = arp()
    r.hwsrc = src_mac
    r.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
    r.opcode = arp.REQUEST
    r.protosrc = IPAddr(gw)
    r.protodst = IPAddr(target_ip)
    e = ethernet(type=ethernet.ARP_TYPE, src=src_mac, dst=r.hwdst)
    e.payload = r
    
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    connections[target_dpid].send(msg)
    log.info("Smart ARP: Router requesting %s on s%s" % (target_ip, target_dpid))

def handle_arp_request(packet, packet_in, event):
    """Xử lý ARP Request (Proxy ARP cho Gateway / Flood cho nội bộ)"""
    arp_packet = packet.payload
    target_ip = str(arp_packet.protodst)
    source_ip = str(arp_packet.protosrc)
    
    learn_location(source_ip, event.dpid, packet_in.in_port)
    arp_cache[source_ip] = arp_packet.hwsrc
    
    # CASE 1: ARP cho Gateway -> Router trả lời
    if target_ip in router_interfaces:
        reply_mac = router_interfaces[target_ip]
        arp_reply = arp()
        arp_reply.hwsrc = reply_mac
        arp_reply.hwdst = arp_packet.hwsrc
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = IPAddr(target_ip)
        arp_reply.protodst = IPAddr(source_ip)
        
        ether = ethernet(type=ethernet.ARP_TYPE, src=reply_mac, dst=arp_packet.hwsrc)
        ether.payload = arp_reply
        
        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=packet_in.in_port))
        event.connection.send(msg)
        return

    # CASE 2: ARP nội bộ (Host tìm Host) -> Flood trong subnet
    gw = find_gateway_for_ip(target_ip)
    if not gw: return
    target_subnet_dpid = gateway_ip_to_dpid.get(gw)
    
    # Chặn ARP lan sang subnet khác
    if event.dpid != target_subnet_dpid: return 

    msg = of.ofp_packet_out()
    msg.data = packet_in.data
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)

def handle_arp_reply(packet, packet_in, event):
    """Xử lý ARP Reply và Forward về host yêu cầu"""
    arp_packet = packet.payload
    src_ip = str(arp_packet.protosrc)
    dst_ip = str(arp_packet.protodst)
    
    arp_cache[src_ip] = arp_packet.hwsrc
    learn_location(src_ip, event.dpid, packet_in.in_port)
    log.info("ARP Learned: %s -> %s" % (src_ip, arp_packet.hwsrc))
    
    # Xử lý hàng đợi
    if src_ip in packet_queue:
        for item in packet_queue[src_ip]:
            handle_ip_packet(item['packet'], item['packet_in'], item['event'])
        del packet_queue[src_ip]

    if dst_ip in router_interfaces: return

    # Forward ARP Reply về cho host
    if dst_ip in ip_to_location:
        (dst_dpid, dst_port) = ip_to_location[dst_ip]
        if dst_dpid == event.dpid:
            msg = of.ofp_packet_out()
            msg.data = packet_in.data
            msg.actions.append(of.ofp_action_output(port=dst_port))
            event.connection.send(msg)
            return

    # Fallback flood nếu chưa biết vị trí
    msg = of.ofp_packet_out()
    msg.data = packet_in.data
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)