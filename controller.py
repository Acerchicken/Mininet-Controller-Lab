# -*- coding: utf-8 -*-
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.util as poxutil
from pox.lib.recoco import Timer
from pox.openflow.discovery import Discovery
import socket

log = core.getLogger()
import arp_handler, firewall, flow_installer, ip_handler

# =============================================================================
# 0. GLOBAL CONFIGURATION & STATE
# =============================================================================

MONITOR_IP = "127.0.0.1"
MONITOR_PORT = 6666

# Protocols
IP_TCP_PROTOCOL = ipv4.TCP_PROTOCOL
IP_UDP_PROTOCOL = ipv4.UDP_PROTOCOL
IP_ICMP_PROTOCOL = ipv4.ICMP_PROTOCOL
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

# Routing Table
routing_table = [
    {'network': '10.0.1.0/24', 'gateway': '10.0.1.1'},
    {'network': '10.0.2.0/24', 'gateway': '10.0.2.1'},
    {'network': '10.0.3.0/24', 'gateway': '10.0.3.1'},
]

# Router Interfaces (MACs changed to avoid conflict with Hosts)
router_interfaces = {
    '10.0.1.1': EthAddr('00:00:00:00:01:01'),
    '10.0.2.1': EthAddr('00:00:00:00:02:01'),
    '10.0.3.1': EthAddr('00:00:00:00:03:01'),
}

# ACL Rules (Yêu cầu 4)
ACL = [
  ("ingress_s1", "TCP", 22, "DENY", "Block SSH to s1"),
  ("ingress_s2", "TCP", 80, "DENY", "Block HTTP to s2"),
  ("ingress_s2", "UDP", 53, "ALLOW", "Allow DNS")
]

# Switch Mappings
switch_name_to_dpid = { "s1": 1, "s2": 2, "s3": 3 }
dpid_to_switch_name = {v: k for k, v in switch_name_to_dpid.items()}

gateway_ip_to_dpid = {
    '10.0.1.1': 1,
    '10.0.2.1': 2,
    '10.0.3.1': 3
}

# GLOBAL STATE
arp_cache = {}
packet_queue = {}
connections = {}
ip_to_location = {} 
adjacency = {} 

monitor_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# --- HELPER FUNCTIONS ---
def ip_in_network(ip, network):
    try:
        ip_addr = IPAddr(ip)
        net_addr, prefix = network.split('/')
        mask = (0xFFFFFFFF << (32 - int(prefix))) & 0xFFFFFFFF
        return (ip_addr.toUnsigned() & mask) == (IPAddr(net_addr).toUnsigned() & mask)
    except: return False

def find_gateway_for_ip(dst_ip):
    for entry in routing_table:
        if ip_in_network(dst_ip, entry['network']): return entry['gateway']
    return None

def is_switch_port(dpid, port):
    if dpid in adjacency:
        if port in adjacency[dpid].values(): return True
    return False

def learn_location(ip, dpid, port):
    # Only learn from host ports, ignore inter-switch links
    if is_switch_port(dpid, port): return
    if ip not in ip_to_location or ip_to_location[ip] != (dpid, port):
        ip_to_location[ip] = (dpid, port)
        log.debug("Learned: %s at s%s-eth%s" % (ip, dpid, port))

def get_next_hop_port(src_dpid, dst_dpid):
    """BFS for Anti-Loop Routing"""
    if src_dpid == dst_dpid: return None
    queue = [(src_dpid, [])]
    visited = set()
    while queue:
        (node, path) = queue.pop(0)
        if node in visited: continue
        visited.add(node)
        if node == dst_dpid:
            if not path: return None
            next_node = path[0]
            if src_dpid in adjacency and next_node in adjacency[src_dpid]:
                return adjacency[src_dpid][next_node]
            return None
        if node in adjacency:
            for neighbor in adjacency[node]:
                queue.append((neighbor, path + [neighbor]))
    return None


# =============================================================================
# 1. YÊU CẦU 1: ARP HANDLER (arp_handler.py)
# =============================================================================


# =============================================================================
# 2. YÊU CẦU 3: FLOW INSTALLATION (flow_installer.py)
# =============================================================================


# =============================================================================
# 3. YÊU CẦU 2: IP PACKET HANDLER (ip_handler.py)
# =============================================================================


# =============================================================================
# 4. YÊU CẦU 4: FIREWALL (firewall.py)
# =============================================================================


# =============================================================================
# 5. YÊU CẦU 5: MONITORING (monitor.py)
# =============================================================================

def send_stats_request():
    for connection in connections.values():
        connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

def handle_flow_stats(event):
    """Xử lý thống kê và gửi qua UDP cho Dashboard"""
    dpid = event.connection.dpid
    host_stats = {}

    for f in event.stats:
        if f.match.dl_type != ethernet.IP_TYPE: continue
        bytes_count = f.byte_count
        proto = f.match.nw_proto 
        
        # RX (Destination)
        if f.match.nw_dst:
            dst_ip = str(f.match.nw_dst)
            if dst_ip not in router_interfaces:
                if dst_ip not in host_stats: 
                    host_stats[dst_ip] = {'rx_total': 0, 'rx_tcp': 0, 'rx_udp': 0, 'rx_icmp': 0, 'tx_total': 0, 'tx_tcp': 0, 'tx_udp': 0, 'tx_icmp': 0}
                
                s = host_stats[dst_ip]
                s['rx_total'] += bytes_count
                if proto == 6: s['rx_tcp'] += bytes_count
                elif proto == 17: s['rx_udp'] += bytes_count
                elif proto == 1: s['rx_icmp'] += bytes_count

        # TX (Source)
        if f.match.nw_src:
            src_ip = str(f.match.nw_src)
            if src_ip not in router_interfaces:
                if src_ip not in host_stats:
                    host_stats[src_ip] = {'rx_total': 0, 'rx_tcp': 0, 'rx_udp': 0, 'rx_icmp': 0, 'tx_total': 0, 'tx_tcp': 0, 'tx_udp': 0, 'tx_icmp': 0}
                
                s = host_stats[src_ip]
                s['tx_total'] += bytes_count
                if proto == 6: s['tx_tcp'] += bytes_count
                elif proto == 17: s['tx_udp'] += bytes_count
                elif proto == 1: s['tx_icmp'] += bytes_count

    for ip, s in host_stats.items():
        if s['rx_total'] == 0 and s['tx_total'] == 0: continue
        msg = "Switch s%s | Host: %-10s | RX: %-6s (TCP:%s UDP:%s ICMP:%s) | TX: %-6s (TCP:%s UDP:%s ICMP:%s)" % (
            dpid, ip, 
            s['rx_total'], s['rx_tcp'], s['rx_udp'], s['rx_icmp'],
            s['tx_total'], s['tx_tcp'], s['tx_udp'], s['tx_icmp']
        )
        try: monitor_sock.sendto(msg.encode('utf-8'), (MONITOR_IP, MONITOR_PORT))
        except: pass


# =============================================================================
# 6. CONTROLLER CORE
# =============================================================================

def _handle_ConnectionUp(event):
    connections[event.dpid] = event.connection
    log.info("Switch s%s connected" % event.dpid)
    install_acl(event.connection, event.dpid)

def _handle_LinkEvent(event):
    l = event.link
    if l.dpid1 not in adjacency: adjacency[l.dpid1] = {}
    adjacency[l.dpid1][l.dpid2] = l.port1
    log.info("Link Discovery: s%s -> s%s on port %s" % (l.dpid1, l.dpid2, l.port1))

def _handle_PacketIn(event):
    if not event.parsed: return
    if event.parsed.type == ethernet.ARP_TYPE:
        if event.parsed.payload.opcode == arp.REQUEST: handle_arp_request(event.parsed, event.ofp, event)
        else: handle_arp_reply(event.parsed, event.ofp, event)
    elif event.parsed.type == ethernet.IP_TYPE:
        handle_ip_packet(event.parsed, event.ofp, event)

def launch():
    def start_discovery(): core.openflow_discovery.addListeners(core)
    core.call_when_ready(start_discovery, "openflow_discovery")
    core.openflow_discovery.addListenerByName("LinkEvent", _handle_LinkEvent)
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    
    core.openflow.addListenerByName("FlowStatsReceived", handle_flow_stats)
    
    Timer(5, send_stats_request, recurring=True)
    log.info("Triangle Router (RX/TX Monitor) Started")