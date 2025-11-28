# =============================================================================
# 4. YÊU CẦU 4: FIREWALL (firewall.py)
# =============================================================================

def install_acl(connection, dpid):
    sw_name = dpid_to_switch_name.get(dpid)
    if not sw_name: return
    acl_key = "ingress_" + sw_name
    
    for (rule_sw, proto, port, action, desc) in ACL:
        if rule_sw == acl_key:
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_proto = IP_TCP_PROTOCOL if proto == "TCP" else IP_UDP_PROTOCOL
            msg.match.tp_dst = port
            
            if action == "DENY": msg.actions = []
            elif action == "ALLOW": msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            
            connection.send(msg)
            log.info("Firewall: %s on %s" % (desc, sw_name))