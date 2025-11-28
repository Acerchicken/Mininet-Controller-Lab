# =============================================================================
# 2. YÊU CẦU 3: FLOW INSTALLATION (flow_installer.py)
# =============================================================================
def install_route_flow(event, packet, src_ip, dst_ip, src_mac, dst_mac, out_port):
    """
    Cài đặt Flow L3 với Priority 50.
    Match đầy đủ 5-tuple (Src IP, Dst IP, Proto) để hỗ trợ Monitor TX/RX.
    """
    fm = of.ofp_flow_mod()
    fm.match.dl_type = ethernet.IP_TYPE
    
    # Match IP Header
    fm.match.nw_src = IPAddr(src_ip) 
    fm.match.nw_dst = IPAddr(dst_ip)
    fm.match.nw_proto = packet.protocol # TCP/UDP/ICMP

    fm.priority = 50
    fm.idle_timeout = 100
    
    # Actions: Rewrite MAC & Output
    fm.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
    fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
    fm.actions.append(of.ofp_action_output(port=out_port))
    
    event.connection.send(fm)