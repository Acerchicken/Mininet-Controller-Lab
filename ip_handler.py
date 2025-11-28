# =============================================================================
# 3. YÊU CẦU 2: IP PACKET HANDLER (ip_handler.py)
# =============================================================================
def handle_ip_packet(packet, packet_in, event):
    ip_packet = packet.payload
    if not isinstance(ip_packet, ipv4): return
    
    src_ip = str(ip_packet.srcip)
    dst_ip = str(ip_packet.dstip)
    
    learn_location(src_ip, event.dpid, packet_in.in_port)
    
    # 1. Ping Router Interface
    if dst_ip in router_interfaces:
        if ip_packet.protocol == IP_ICMP_PROTOCOL and ip_packet.payload.type == ICMP_ECHO_REQUEST:
            icmp_req = ip_packet.payload
            icmp_rep = icmp(type=ICMP_ECHO_REPLY, code=0, payload=icmp_req.payload)
            ip_rep = ipv4(protocol=IP_ICMP_PROTOCOL, srcip=ip_packet.dstip, dstip=ip_packet.srcip, payload=icmp_rep)
            eth_rep = ethernet(type=ethernet.IP_TYPE, src=packet.dst, dst=packet.src, payload=ip_rep)
            msg = of.ofp_packet_out(data=eth_rep.pack())
            msg.actions.append(of.ofp_action_output(port=packet_in.in_port))
            event.connection.send(msg)
        return

    # 2. Logic Queue & ARP Request
    if dst_ip not in arp_cache or dst_ip not in ip_to_location:
        if dst_ip not in packet_queue:
            packet_queue[dst_ip] = []
            send_arp_request_smart(dst_ip)
        packet_queue[dst_ip].append({'packet': packet, 'packet_in': packet_in, 'event': event})
        return

    # 3. Logic Forwarding (Routing)
    dst_mac = arp_cache[dst_ip]
    (dst_dpid, host_port) = ip_to_location[dst_ip]
    src_gw = find_gateway_for_ip(dst_ip)
    src_mac = router_interfaces[src_gw]
    
    out_port = None
    if event.dpid == dst_dpid:
        out_port = host_port # Last Hop
    else:
        out_port = get_next_hop_port(event.dpid, dst_dpid) # Next Hop (BFS)
        if out_port is None: return # Drop to avoid loop

    # Gửi Packet hiện tại
    msg = of.ofp_packet_out()
    msg.data = packet_in.data
    msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
    msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
    msg.actions.append(of.ofp_action_output(port=out_port))
    event.connection.send(msg)
    
    # Yêu cầu 3: Cài đặt Flow (Gọi hàm từ mục 2)
    install_route_flow(event, ip_packet, src_ip, dst_ip, src_mac, dst_mac, out_port)

