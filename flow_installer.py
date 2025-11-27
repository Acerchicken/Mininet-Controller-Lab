def install_route_flow(event, dst_ip, dst_mac, src_mac, out_port):
    """Installs a low-priority L3/L4 flow for routing"""
    msg = of.ofp_flow_mod()
    msg.match.dl_type = ethernet.IP_TYPE
    msg.match.nw_dst = IPAddr(dst_ip)
    msg.idle_timeout = 100
    msg.hard_timeout = 200
    
    # LOWER priority (50) than ACL rules (100)
    msg.priority = 50 
    
    # Actions (rewrite MAC and output)
    msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
    msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
    msg.actions.append(of.ofp_action_output(port=out_port))
    
    event.connection.send(msg)
    
    if out_port == of.OFPP_FLOOD:
         log.debug("Installed route flow (flood) on %s for %s" % 
                   (poxutil.dpid_to_str(event.dpid), dst_ip))
    else:
         log.debug("Installed route flow on %s for %s -> port %d" % 
                   (poxutil.dpid_to_str(event.dpid), dst_ip, out_port))