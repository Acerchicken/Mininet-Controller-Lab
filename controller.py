# -*- coding: utf-8 -*-
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.util as poxutil

import arp_handler
import ip_handler
import firewall
import flow_installer

log = core.getLogger()

# ==============================================
# CONSTANTS
# ==============================================
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_CODE_NET_UNREACH = 0

IP_TCP_PROTOCOL = ipv4.TCP_PROTOCOL
IP_UDP_PROTOCOL = ipv4.UDP_PROTOCOL
IP_ICMP_PROTOCOL = ipv4.ICMP_PROTOCOL

# ==============================================
# TOPOLOGY & ROUTING CONFIG
# ==============================================
# Cập nhật cho 3 subnet
routing_table = [
    {'network': '10.0.1.0/24', 'gateway': '10.0.1.1'},
    {'network': '10.0.2.0/24', 'gateway': '10.0.2.1'},
    {'network': '10.0.3.0/24', 'gateway': '10.0.3.1'},
]

# Router MAC addresses
router_interfaces = {
    '10.0.1.1': EthAddr('00:00:00:00:00:01'),
    '10.0.2.1': EthAddr('00:00:00:00:00:02'),
    '10.0.3.1': EthAddr('00:00:00:00:00:03'),
}

# Mapping DPID
switch_name_to_dpid = {
    "s1": 1,
    "s2": 2,
    "s3": 3,
}
dpid_to_switch_name = {v: k for k, v in switch_name_to_dpid.items()}

# ==============================================
# FIREWALL RULES (ACL)
# ==============================================
# Rule: (Switch_Loc, Proto, Port, Action, Desc)
ACL = [
  ("ingress_s1", "TCP", 22, "DENY", "Block SSH to network behind s1"),
  ("ingress_s2", "TCP", 80, "DENY", "Block HTTP to network behind s2"),
  ("ingress_s2", "UDP", 53, "ALLOW", "Allow DNS"),
  # Bạn có thể thêm rule cho s3 nếu cần
]
dpid_to_switch_name = {v: k for k, v in switch_name_to_dpid.items()}

# ==============================================
# 2. GLOBAL STATE
# ==============================================

# ARP Cache: save mapping IP -> MAC
arp_cache = {}

# Packet Queue: save packets waiting ARP reply
packet_queue = {}

# Stores the connection object for each switch
connections = {} # dpid -> event.connection
# Stores the location (dpid, port) for each host IP
ip_to_location = {} # IP -> (dpid, port)


# ==============================================
# 3. HELPER FUNCTIONS (Utils)
# ==============================================

def ip_in_network(ip, network):
    """Checks if an IP is within a CIDR network"""
    try:
        ip_addr = IPAddr(ip)
        net_addr, prefix = network.split('/')
        net_addr = IPAddr(net_addr)
        prefix = int(prefix)
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return (ip_addr.toUnsigned() & mask) == (net_addr.toUnsigned() & mask)
    except:
        return False

def find_gateway_for_ip(dst_ip):
    """Finds the gateway IP for a destination IP"""
    for entry in routing_table:
        if ip_in_network(dst_ip, entry['network']):
            return entry['gateway']
    return None

def find_network_for_gateway(gateway_ip):
    """Finds the network for a gateway IP"""
    for entry in routing_table:
        if entry['gateway'] == gateway_ip:
            return entry['network']
    return None

def learn_location(ip, dpid, port):
    """Learns the mapping of IP -> (dpid, port)"""
    if ip not in ip_to_location or ip_to_location[ip] != (dpid, port):
        ip_to_location[ip] = (dpid, port)
        log.debug("Learned: %s is on switch %s port %d" % (ip, poxutil.dpid_to_str(dpid), port))


# ==============================================
# 4. LAYER 2 (ARP) HANDLING
# ==============================================

# ==============================================
# 5. LAYER 3 (IP & ICMP) HANDLING
# ==============================================


# ==============================================
# 6. LAYER 4 (ACL) & FLOW INSTALLATION
# ==============================================






# ==============================================
# 7. POX CONTROL PLANE (Event Handlers)
# ==============================================

def _handle_ConnectionUp(event):
    """
    Called when a switch connects.
    Proactively installs L4 ACL rules immediately.
    """
    dpid = event.dpid
    dpid_str = poxutil.dpid_to_str(dpid)
    log.info("Switch %s has connected." % dpid_str)
    connections[dpid] = event.connection
    
    # Install L4 ACL rules as soon as the switch is up
    install_acl_rules(event.connection, dpid)

def _handle_ConnectionDown(event):
    """Called when a switch disconnects."""
    dpid = event.dpid
    dpid_str = poxutil.dpid_to_str(dpid)
    log.info("Switch %s has disconnected." % dpid_str)
    if dpid in connections:
        del connections[dpid]
    
    # Clear location cache for hosts on that switch
    ips_to_remove = [ip for ip, (sw_dpid, port) in ip_to_location.items() if sw_dpid == dpid]
    for ip in ips_to_remove:
        log.debug("Forgetting location of %s (switch %s down)" % (ip, dpid_str))
        del ip_to_location[ip]

def _handle_PacketIn(event):
    """
    Main PacketIn handler.
    Only called for packets that DON'T match a high-priority rule.
    (e.g., ARP packets, or the first IP packet of a new flow)
    """
    packet = event.parsed
    packet_in = event.ofp
    
    if not packet.parsed:
        log.warning("Ignoring incomplete packet")
        return
    
    # 1. Classify L2 packets
    if packet.type == ethernet.ARP_TYPE:
        arp_packet = packet.payload
        if arp_packet.opcode == arp.REQUEST:
            handle_arp_request(arp_packet, packet_in, event, event.dpid)
        elif arp_packet.opcode == arp.REPLY:
            handle_arp_reply(arp_packet, packet_in, event, event.dpid)
    
    # 2. Classify L3 packets
    elif packet.type == ethernet.IP_TYPE:
        ip_packet = packet.payload
        # Hand off to the L3 handler
        handle_ip_packet(ip_packet, packet, packet_in, event)


# ==============================================
# 8. LAUNCH FUNCTION
# ==============================================

def launch():
    """POX controller launch function"""
    # Register event handlers
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("ConnectionDown", _handle_ConnectionDown)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    
    log.info("ACL Router controller (multi-switch, corrected) started")
    log.info("Routing table:")
    for entry in routing_table:
        log.info("  %s via %s" % (entry['network'], entry['gateway']))