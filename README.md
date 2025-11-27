SDN Layer 3 Router with Firewall & Real-time Monitoring
Dự án này triển khai một SDN Controller hoàn chỉnh sử dụng POX Framework. Hệ thống hoạt động như một Router Layer 3 trên topo mạng hình tam giác (Ring Topology), tích hợp khả năng chống Loop, Firewall tầng 4 (ACL) và hệ thống giám sát lưu lượng thời gian thực tách biệt.

🚀 Tính năng nổi bật
Advanced L3 Routing (Chống Loop):

Sử dụng thuật toán BFS (Breadth-First Search) để tìm đường đi ngắn nhất giữa các switch.

Thay thế cơ chế Flood truyền thống bằng Unicast Routing, ngăn chặn Broadcast Storm trong topo mạng vòng.

Smart ARP Handling:

Proxy ARP: Router tự động trả lời ARP Request cho Gateway.

Intra-subnet: Hỗ trợ ARP flood nội bộ để các host cùng subnet nhìn thấy nhau (L2 Switching).

Smart Inter-subnet ARP: Controller chỉ gửi ARP Request đến đúng switch đích, không flood toàn mạng.

Firewall Layer 4 (ACL):

Chặn/Cho phép traffic dựa trên giao thức (TCP/UDP) và Port.

Cơ chế cài đặt Flow chủ động (Proactive) ngay khi Switch kết nối.

Real-time Monitoring:

Hệ thống giám sát tách biệt chạy trên Terminal riêng.

Giao tiếp với Controller qua UDP Socket để hiển thị thống kê (TCP/UDP/ICMP/ARP bytes) mỗi 5 giây.

Không làm rác log của Controller chính.

🗺️ Topology Mạng
Hệ thống mô phỏng 3 Subnet kết nối theo hình tam giác:

Plaintext

      [h1, h2]           [h3, h4]           [h5, h6]
         |                  |                  |
    (10.0.1.0/24)      (10.0.2.0/24)      (10.0.3.0/24)
         |                  |                  |
       [s1]---------------[s2]---------------[s3]
         \_____________________________________/
s1: Gateway 10.0.1.1 (MAC: ...:01:01)

s2: Gateway 10.0.2.1 (MAC: ...:02:01)

s3: Gateway 10.0.3.1 (MAC: ...:03:01)

🛠️ Yêu cầu hệ thống
OS: Ubuntu (Khuyên dùng máy ảo Mininet VM có sẵn).

Software:

Mininet

Python 2.7 (Môi trường POX)

POX Controller

📂 Cấu trúc thư mục
Bash

.
├── controller.py          # Code chính của SDN Controller (L3 Routing, ARP, ACL)
├── monitor.py             # Dashboard hiển thị thông số (Server UDP)
├── multi_router_topo.py   # Script tạo Topology Mininet (3 switches tam giác)
└── README.md              # Tài liệu hướng dẫn
⚙️ Hướng dẫn cài đặt & Chạy
Bước 1: Chuẩn bị mã nguồn
Copy file controller.py vào thư mục ext của POX (thường là ~/pox/pox/ext/) để dễ dàng import module. File monitor.py và multi_router_topo.py có thể để ở thư mục home (~).

Bước 2: Chạy Dashboard Giám sát (Terminal 1)
Mở một terminal mới và chạy file monitor. Nó sẽ lắng nghe ở port 6666.

Bash

python monitor.py
Màn hình sẽ hiện: Waiting for data from Controller...

Bước 3: Khởi chạy Controller (Terminal 2)
Mở terminal thứ 2, di chuyển vào thư mục pox và chạy lệnh sau. Lưu ý: Bắt buộc phải có module openflow.discovery để controller vẽ được bản đồ mạng.

Bash

cd ~/pox
./pox.py openflow.discovery controller
(Giả sử bạn đặt tên file trong thư mục ext là controller.py. Nếu đặt tên khác, hãy thay đổi tương ứng, ví dụ router_controller).

Bước 4: Khởi chạy Mininet (Terminal 3)
Mở terminal thứ 3 và chạy topo mạng.

Bash

sudo mn --custom multi_router_topo.py --topo mytopo --controller remote,ip=127.0.0.1 --mac
🧪 Kịch bản Kiểm thử (Test Cases)
Sau khi hệ thống khởi động khoảng 10 giây (để Controller khám phá xong các liên kết), bạn có thể thực hiện các bài test sau:

1. Kiểm tra kết nối (Ping)
Tại giao diện Mininet:

Bash

mininet> pingall
Kết quả mong đợi: Lần đầu có thể mất vài gói do ARP learning, nhưng lần chạy thứ 2 phải thông suốt 100%.

2. Kiểm tra Firewall (ACL)
Luật Firewall mặc định:

s1: Chặn SSH (Port 22).

s2: Chặn HTTP (Port 80).

Test chặn SSH vào s1:

Bash

mininet> h3 nc -zv 10.0.1.2 22
Kết quả: Connection timed out (Gói tin bị Drop).

Test chặn HTTP vào s2:

Bash

mininet> h1 nc -zv 10.0.2.2 80
Kết quả: Connection timed out (Gói tin bị Drop).

Test dịch vụ cho phép (DNS - UDP 53):

Bash

mininet> h1 nc -u -zv 10.0.2.2 53
Kết quả: Gói tin đi qua được (Switch không drop, dù host không mở port thì cũng không bị timeout).

3. Kiểm tra Giám sát (Monitor)
Quan sát Terminal 1, bạn sẽ thấy thông số lưu lượng cập nhật mỗi 5 giây. Hãy thử ping liên tục để thấy chỉ số ICMP tăng lên:

Bash

mininet> h1 ping h5
📝 Giải thích kỹ thuật (Dành cho Dev)
Vấn đề Loop & Broadcast Storm:

Trong mạng vòng, nếu dùng FLOOD, gói tin sẽ chạy vô tận.

Giải pháp: Controller sử dụng module discovery để xây dựng đồ thị mạng. Khi cần chuyển gói tin giữa các switch, nó dùng thuật toán tìm đường (BFS) để xác định một cổng ra duy nhất.

Vấn đề ARP:

Controller chặn ARP request lan truyền tự do giữa các subnet.

Nó đóng vai trò Proxy trả lời cho Gateway.

Nó đóng vai trò L2 Switch cho các host cùng subnet.

Vấn đề Flow Table:

Routing Flow được cài đặt với priority=50, idle_timeout=100.

Firewall Flow được cài đặt với priority=100 (Vĩnh viễn).

ARP Flow được cài đặt với priority=1 để đếm gói tin ARP cho Monitor.
