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