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

# ==============================================
# 1. CONFIGURATION
# ==============================================

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

# Router Interfaces
router_interfaces = {
    '10.0.1.1': EthAddr('00:00:00:00:01:01'),
    '10.0.2.1': EthAddr('00:00:00:00:02:01'),
    '10.0.3.1': EthAddr('00:00:00:00:03:01'),
}

# ACL Rules
ACL = [
  ("ingress_s1", "TCP", 22, "DENY", "Block SSH to s1"),
  ("ingress_s2", "TCP", 80, "DENY", "Block HTTP to s2"),
  ("ingress_s2", "UDP", 53, "ALLOW", "Allow DNS")
]

# Mappings
switch_name_to_dpid = { "s1": 1, "s2": 2, "s3": 3 }
dpid_to_switch_name = {v: k for k, v in switch_name_to_dpid.items()}

gateway_ip_to_dpid = {
    '10.0.1.1': 1,
    '10.0.2.1': 2,
    '10.0.3.1': 3
}

# ==============================================
# 2. GLOBAL STATE
# ==============================================
arp_cache = {}
packet_queue = {}
connections = {}
ip_to_location = {} 
adjacency = {} 

monitor_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# ==============================================
# 3. HELPER FUNCTIONS
# ==============================================

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
    if is_switch_port(dpid, port): return
    if ip not in ip_to_location or ip_to_location[ip] != (dpid, port):
        ip_to_location[ip] = (dpid, port)
        log.debug("Learned: %s at s%s-eth%s" % (ip, dpid, port))

def get_next_hop_port(src_dpid, dst_dpid):
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
                port = adjacency[src_dpid][next_node]
                # --- THÊM LOG ---
                log.debug("Path found: s%s -> s%s (via port %s)" % (src_dpid, dst_dpid, port))
                return port
            return None
        if node in adjacency:
            for neighbor in adjacency[node]:
                queue.append((neighbor, path + [neighbor]))
    
    # --- THÊM LOG KHI KHÔNG TÌM THẤY ĐƯỜNG ---
    log.warning("No path found from s%s to s%s. Adjacency: %s" % (src_dpid, dst_dpid, adjacency.keys()))
    return None

# ==============================================
# 4. MONITORING (FULL RX/TX TRACKING)
# ==============================================

def send_stats_request():
    for connection in connections.values():
        connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

def handle_flow_stats(event):
    """
    Phiên bản Chi tiết: Tách biệt thống kê Protocol cho chiều Gửi (TX) và Nhận (RX).
    """
    dpid = event.connection.dpid
    
    # Cấu trúc dữ liệu mới:
    # { 
    #   '10.0.0.1': {
    #       'rx_total': 0, 'rx_tcp': 0, 'rx_udp': 0, 'rx_icmp': 0,
    #       'tx_total': 0, 'tx_tcp': 0, 'tx_udp': 0, 'tx_icmp': 0
    #   } 
    # }
    host_stats = {}

    for f in event.stats:
        # Chỉ quan tâm Flow IP
        if f.match.dl_type != ethernet.IP_TYPE:
            continue
            
        bytes_count = f.byte_count
        proto = f.match.nw_proto # 6=TCP, 17=UDP, 1=ICMP
        
        # ============================================
        # 1. XỬ LÝ BÊN NHẬN (Destination - RX)
        # ============================================
        if f.match.nw_dst:
            dst_ip = str(f.match.nw_dst)
            if dst_ip not in router_interfaces:
                # Khởi tạo nếu chưa có
                if dst_ip not in host_stats: 
                    host_stats[dst_ip] = {
                        'rx_total': 0, 'rx_tcp': 0, 'rx_udp': 0, 'rx_icmp': 0,
                        'tx_total': 0, 'tx_tcp': 0, 'tx_udp': 0, 'tx_icmp': 0
                    }
                
                stats = host_stats[dst_ip]
                stats['rx_total'] += bytes_count
                
                if proto == 6: stats['rx_tcp'] += bytes_count
                elif proto == 17: stats['rx_udp'] += bytes_count
                elif proto == 1: stats['rx_icmp'] += bytes_count

        # ============================================
        # 2. XỬ LÝ BÊN GỬI (Source - TX)
        # ============================================
        if f.match.nw_src:
            src_ip = str(f.match.nw_src)
            if src_ip not in router_interfaces:
                # Khởi tạo nếu chưa có
                if src_ip not in host_stats:
                    host_stats[src_ip] = {
                        'rx_total': 0, 'rx_tcp': 0, 'rx_udp': 0, 'rx_icmp': 0,
                        'tx_total': 0, 'tx_tcp': 0, 'tx_udp': 0, 'tx_icmp': 0
                    }
                
                stats = host_stats[src_ip]
                stats['tx_total'] += bytes_count

                if proto == 6: stats['tx_tcp'] += bytes_count
                elif proto == 17: stats['tx_udp'] += bytes_count
                elif proto == 1: stats['tx_icmp'] += bytes_count

    # ============================================
    # 3. TẠO FORMAT TIN NHẮN & GỬI UDP
    # ============================================
    for ip, s in host_stats.items():
        # Chỉ gửi nếu có hoạt động
        if s['rx_total'] == 0 and s['tx_total'] == 0: continue
            
        # Format tin nhắn: Chia làm 2 phần RX [...] và TX [...]
        # Ví dụ: Switch s1 | Host: 10.0.1.2 | RX: 100 (TCP:0...) | TX: 50 (TCP:0...)
        
        msg = "Switch s%s | Host: %-10s | RX: %-6s (TCP:%s UDP:%s ICMP:%s) | TX: %-6s (TCP:%s UDP:%s ICMP:%s)" % (
            dpid, ip, 
            s['rx_total'], s['rx_tcp'], s['rx_udp'], s['rx_icmp'],
            s['tx_total'], s['tx_tcp'], s['tx_udp'], s['tx_icmp']
        )
        
        try: 
            monitor_sock.sendto(msg.encode('utf-8'), (MONITOR_IP, MONITOR_PORT))
        except: pass

# ==============================================
# 5. PACKET HANDLING
# ==============================================

def handle_arp_request(packet, packet_in, event):
    arp_packet = packet.payload
    target_ip = str(arp_packet.protodst)
    source_ip = str(arp_packet.protosrc)
    
    learn_location(source_ip, event.dpid, packet_in.in_port)
    arp_cache[source_ip] = arp_packet.hwsrc
    
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

    gw = find_gateway_for_ip(target_ip)
    if not gw: return
    target_subnet_dpid = gateway_ip_to_dpid.get(gw)
    
    if event.dpid != target_subnet_dpid: return 

    msg = of.ofp_packet_out()
    msg.data = packet_in.data
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)

def handle_arp_reply(packet, packet_in, event):
    arp_packet = packet.payload
    src_ip = str(arp_packet.protosrc)
    dst_ip = str(arp_packet.protodst)
    
    arp_cache[src_ip] = arp_packet.hwsrc
    learn_location(src_ip, event.dpid, packet_in.in_port)
    
    if src_ip in packet_queue:
        for item in packet_queue[src_ip]:
            handle_ip_packet(item['packet'], item['packet_in'], item['event'])
        del packet_queue[src_ip]

    if dst_ip in router_interfaces: return

    if dst_ip in ip_to_location:
        (dst_dpid, dst_port) = ip_to_location[dst_ip]
        if dst_dpid == event.dpid:
            msg = of.ofp_packet_out()
            msg.data = packet_in.data
            msg.actions.append(of.ofp_action_output(port=dst_port))
            event.connection.send(msg)
            return

    msg = of.ofp_packet_out()
    msg.data = packet_in.data
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)

def send_arp_request_smart(target_ip):
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

def handle_ip_packet(packet, packet_in, event):
    ip_packet = packet.payload
    if not isinstance(ip_packet, ipv4): return
    
    src_ip = str(ip_packet.srcip)
    dst_ip = str(ip_packet.dstip)
    
    learn_location(src_ip, event.dpid, packet_in.in_port)
    
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

    if dst_ip not in arp_cache or dst_ip not in ip_to_location:
        if dst_ip not in packet_queue:
            packet_queue[dst_ip] = []
            send_arp_request_smart(dst_ip)
        packet_queue[dst_ip].append({'packet': packet, 'packet_in': packet_in, 'event': event})
        return

    dst_mac = arp_cache[dst_ip]
    (dst_dpid, host_port) = ip_to_location[dst_ip]
    src_gw = find_gateway_for_ip(dst_ip)
    src_mac = router_interfaces[src_gw]
    
    out_port = None
    if event.dpid == dst_dpid:
        out_port = host_port
    else:
        out_port = get_next_hop_port(event.dpid, dst_dpid)
        if out_port is None: return 

    msg = of.ofp_packet_out()
    msg.data = packet_in.data
    msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
    msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
    msg.actions.append(of.ofp_action_output(port=out_port))
    event.connection.send(msg)
    
    # --- Cài Flow (QUAN TRỌNG ĐỂ ĐẾM TX) ---
    fm = of.ofp_flow_mod()
    fm.match.dl_type = ethernet.IP_TYPE
    
    # 1. Match cả Source để đếm TX của thằng gửi
    fm.match.nw_src = IPAddr(src_ip) 
    
    # 2. Match Destination để đếm RX của thằng nhận
    fm.match.nw_dst = IPAddr(dst_ip)
    
    # 3. Match Protocol để phân loại
    fm.match.nw_proto = ip_packet.protocol

    fm.priority = 50
    fm.idle_timeout = 100
    fm.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
    fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
    fm.actions.append(of.ofp_action_output(port=out_port))
    event.connection.send(fm)

# ==============================================
# 6. INIT & ACL
# ==============================================

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

def _handle_ConnectionUp(event):
    connections[event.dpid] = event.connection
    log.info("Switch s%s connected" % event.dpid)
    install_acl(event.connection, event.dpid)

def _handle_LinkEvent(event):
    l = event.link
    if l.dpid1 not in adjacency: adjacency[l.dpid1] = {}
    adjacency[l.dpid1][l.dpid2] = l.port1
    
    # In ra để debug 
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