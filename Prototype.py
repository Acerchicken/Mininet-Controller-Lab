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

# Router Interfaces (SỬA MAC ĐỂ TRÁNH TRÙNG VỚI HOST)
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
    # Chỉ học vị trí host, không học từ cổng nối switch
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
                return adjacency[src_dpid][next_node]
            return None
        if node in adjacency:
            for neighbor in adjacency[node]:
                queue.append((neighbor, path + [neighbor]))
    return None

# ==============================================
# 4. MONITORING (FIXED VERSION)
# ==============================================

def send_stats_request():
    # Gửi request đến tất cả switch đang kết nối
    # log.info("Monitor: Sending stats request to %d switches..." % len(connections))
    for connection in connections.values():
        connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

def handle_flow_stats(event):
    tcp_bytes = 0
    udp_bytes = 0
    icmp_bytes = 0
    total_bytes = 0 # Biến mới để đếm tổng
    
    # Lấy DPID từ connection (SỬA LỖI QUAN TRỌNG)
    dpid = event.connection.dpid
    
    for f in event.stats:
        # Cộng dồn tổng lưu lượng của mọi flow
        total_bytes += f.byte_count
        
        # Kiểm tra Protocol (Lưu ý: Flow Routing priority 50 không có nw_proto nên sẽ không vào if này)
        if f.match.nw_proto == 6: 
            tcp_bytes += f.byte_count
        elif f.match.nw_proto == 17: 
            udp_bytes += f.byte_count
        elif f.match.nw_proto == 1: 
            icmp_bytes += f.byte_count
    
    # Format tin nhắn có thêm cột Total
    msg = "Switch s%s | Total: %-8s | TCP: %-8s | UDP: %-8s | ICMP: %-8s" % (
        dpid, total_bytes, tcp_bytes, udp_bytes, icmp_bytes
    )
    
    # Debug log để kiểm tra xem hàm này có chạy không
    # log.info("Monitor: Sending to dashboard -> %s" % msg)

    # Gửi UDP (Bỏ try-except để bắt lỗi nếu có)
    monitor_sock.sendto(msg.encode('utf-8'), (MONITOR_IP, MONITOR_PORT))

# ==============================================
# 5. PACKET HANDLING (FIXED ARP LOGIC)
# ==============================================

def handle_arp_request(packet, packet_in, event):
    arp_packet = packet.payload
    target_ip = str(arp_packet.protodst)
    source_ip = str(arp_packet.protosrc)
    
    learn_location(source_ip, event.dpid, packet_in.in_port)
    arp_cache[source_ip] = arp_packet.hwsrc
    
    # === CASE 1: ARP cho Gateway (Router) ===
    if target_ip in router_interfaces:
        reply_mac = router_interfaces[target_ip]
        # Gửi ARP Reply
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
        # log.info("ARP: Replied for gateway %s" % target_ip)
        return

    # === CASE 2: ARP cho Host khác (Intra-subnet) ===
    # Tìm xem target_ip thuộc subnet nào
    gw = find_gateway_for_ip(target_ip)
    if not gw: return
    
    target_subnet_dpid = gateway_ip_to_dpid.get(gw)
    
    # QUAN TRỌNG: Chặn ARP Broadcast lan sang subnet khác (Router Boundary)
    if event.dpid != target_subnet_dpid:
        # log.debug("ARP: Dropped leakage request for %s on s%s" % (target_ip, event.dpid))
        return 

    # === CASE 3: Nếu đúng switch, FLOOD để host kia tự trả lời
    # (KHÔNG Proxy ARP ở đây, để tránh trùng MAC Router)
    msg = of.ofp_packet_out()
    msg.data = packet_in.data
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)
    # log.debug("ARP: Flooded request for %s on s%s" % (target_ip, event.dpid))

def handle_arp_reply(packet, packet_in, event):
    arp_packet = packet.payload
    src_ip = str(arp_packet.protosrc)
    dst_ip = str(arp_packet.protodst) # IP của người nhận (ví dụ h1)
    
    # 1. Học vị trí và Cập nhật Cache
    arp_cache[src_ip] = arp_packet.hwsrc
    learn_location(src_ip, event.dpid, packet_in.in_port)
    log.info("ARP Learned: %s -> %s" % (src_ip, arp_packet.hwsrc))
    
    # 2. Xử lý gói tin đang chờ (Queue) - Giữ nguyên logic cũ
    if src_ip in packet_queue:
        log.info("Processing queued packets for %s" % src_ip)
        for item in packet_queue[src_ip]:
            handle_ip_packet(item['packet'], item['packet_in'], item['event'])
        del packet_queue[src_ip]

    # ================================================================
    # 3. FIX LỖI: Chuyển tiếp ARP Reply về cho Host yêu cầu (h1)
    # ================================================================
    
    # Nếu gói tin này gửi cho Router (Gateway), ta không cần forward (vì ta đã xử lý ở trên rồi)
    if dst_ip in router_interfaces:
        return

    # Nếu gói tin gửi cho Host khác (h1), ta cần đẩy nó xuống Switch
    # Tìm xem h1 đang ở đâu
    if dst_ip in ip_to_location:
        (dst_dpid, dst_port) = ip_to_location[dst_ip]
        
        # Nếu h1 cùng nằm trên switch này (Intra-subnet thường là vậy)
        if dst_dpid == event.dpid:
            msg = of.ofp_packet_out()
            msg.data = packet_in.data
            msg.actions.append(of.ofp_action_output(port=dst_port))
            event.connection.send(msg)
            # log.debug("ARP: Forwarded reply to %s on port %s" % (dst_ip, dst_port))
            return

    # Nếu không biết h1 ở đâu (hiếm khi xảy ra vì h1 vừa gửi Request), 
    # ta FLOOD để đảm bảo h1 nhận được.
    msg = of.ofp_packet_out()
    msg.data = packet_in.data
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)

def send_arp_request_smart(target_ip):
    # Chỉ dùng khi Router cần tìm Host (Inter-subnet)
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
    
    # 1. Packet gửi tới Router (Ping Gateway)
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

    # 2. Routing Logic
    # Nếu chưa biết MAC đích -> Queue và gửi ARP
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
        if out_port is None: return # Drop để tránh loop nếu chưa có đường

    # Gửi Packet (Rewrite MAC)
    msg = of.ofp_packet_out()
    msg.data = packet_in.data
    msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
    msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
    msg.actions.append(of.ofp_action_output(port=out_port))
    event.connection.send(msg)
    
    # Cài Flow
    fm = of.ofp_flow_mod()
    fm.match.dl_type = ethernet.IP_TYPE
    fm.match.nw_dst = IPAddr(dst_ip)

    # Phân loại Flow theo giao thức (TCP/UDP/ICMP) để Monitor đếm được
    fm.match.nw_proto = ip_packet.protocol

    fm.priority = 50
    fm.idle_timeout = 100
    fm.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
    fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
    fm.actions.append(of.ofp_action_output(port=out_port))
    event.connection.send(fm)
    
    # log.info("Routing: %s -> %s via s%s-eth%s" % (src_ip, dst_ip, event.dpid, out_port))

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
    # log.info("Link: s%s -> s%s (port %s)" % (l.dpid1, l.dpid2, l.port1))

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
    
    # Đăng ký sự kiện thống kê
    core.openflow.addListenerByName("FlowStatsReceived", handle_flow_stats)
    
    # Timer gửi request mỗi 5s
    Timer(5, send_stats_request, recurring=True)
    
    log.info("Triangle Router Started")