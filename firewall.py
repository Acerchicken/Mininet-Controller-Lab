# ==============================================
# 6. LAYER 4 (ACL) & FLOW INSTALLATION
# ==============================================
def install_acl_rules(connection, dpid):
    """
    Proactively installs L4 ACL rules on a switch.
    These rules have a high priority (100).
    """
    switch_name = dpid_to_switch_name.get(dpid)
    if not switch_name:
        log.warning("DPID %s not in name map, skipping ACLs." % dpid)
        return

    log.info("Installing ACL rules on switch %s (DPID: %s)..." % (switch_name, dpid))
    
    acl_key = "ingress_" + switch_name

    for rule in ACL:
        (rule_switch, proto, port, action, desc) = rule
        
        # Apply rule to the correct switch
        if rule_switch == acl_key:
            msg = of.ofp_flow_mod()
            msg.priority = 100 # High priority
            
            # Match L3
            msg.match.dl_type = ethernet.IP_TYPE
            
            # Match L4 Protocol
            if proto == "TCP":
                msg.match.nw_proto = IP_TCP_PROTOCOL
            elif proto == "UDP":
                msg.match.nw_proto = IP_UDP_PROTOCOL
            else:
                log.warning("Unknown protocol '%s' in ACL rule, skipping." % proto)
                continue
                
            # Match L4 Port
            msg.match.tp_dst = port
            
            # Action
            if action == "DENY":
                msg.actions = [] # Empty action list = DROP
                log.info("  -> Installing DENY rule for %s port %d (%s)" % (proto, port, desc))
            elif action == "ALLOW":
                # Send to controller for normal (L3) routing
                msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
                log.info("  -> Installing ALLOW rule for %s port %d (%s)" % (proto, port, desc))
            
            connection.send(msg)