# 🌐 SDN L3 Router with Anti-Loop & Real-Time Monitoring (POX/Mininet)

This project implements a complete Software-Defined Networking (SDN) Layer 3 Router abstraction using the POX controller framework. It manages routing across three distinct subnets interconnected in a loop (triangle) topology, prioritizing stability, performance, and security.

---

## 1. ⚙️ Core Functionalities

This controller provides an end-to-end routing solution featuring:

* **L3 Routing Abstraction:** The OpenFlow switches (`s1`, `s2`, `s3`) are abstracted as ports of a single logical router, enabling communication between the `10.0.1.x`, `10.0.2.x`, and `10.0.3.x` subnets.
* **Anti-Loop Protection (BFS):** Utilizes the `openflow.discovery` module to map the network's triangle topology and implements a **Breadth-First Search (BFS)** algorithm to find the shortest path, effectively preventing broadcast storms and routing loops. 
* **Reactive Flow Installation (Optimized Data Plane):** Flows are installed only after the first packet of a conversation is processed (priority 50), significantly offloading the controller and improving network throughput for subsequent packets.
* **Intra/Inter-Subnet ARP Handler:** Correctly performs Proxy ARP for inter-subnet traffic and handles local ARP requests via secure flooding to avoid MAC confusion and router spoofing.
* **Layer 4 Firewall (ACL):** Proactively installs high-priority (100) firewall rules to drop unwanted traffic at the ingress switch.
* **Real-Time Monitoring:** A separate UDP-based monitor streams live traffic statistics (TCP, UDP, ICMP, Total Bytes) from the switch data planes.

---

## 2. 🗺️ Topology and Setup

The network uses a stable triangle topology (s1-s2-s3-s1) to ensure redundancy, while the controller guarantees loop-free forwarding. 


| Subnet | Hosts | Gateway IP (Router MAC) | Switch DPID |
| :--- | :--- | :--- | :--- |
| **A** | `h1`, `h2` (10.0.1.x) | `10.0.1.1` (`00:00:00:00:01:01`) | 1 |
| **B** | `h3`, `h4` (10.0.2.x) | `10.0.2.1` (`00:00:00:00:02:01`) | 2 |
| **C** | `h5`, `h6` (10.0.3.x) | `10.0.3.1` (`00:00:00:00:00:03:01`) | 3 |

---

## 3. 🚀 Execution Instructions

The system requires two components running simultaneously: the Monitor Dashboard (Receiver) and the POX Controller (Sender/Router).

### A. Prerequisites

1.  **Mininet:** Installed and running (Tested on Mininet 2.3.0 or later). You can install the iso file of Ubuntu that already have mininet and POX installed here: https://github.com/mininet/openflow-tutorial/wiki/Installing-Required-Software
2.  **POX:** Installed and accessible (Tested with POX 0.2.0 carp).
3.  Ensure your topology file (`multi_router_topo.py`) is set up for the triangle topology and fixed ports (as discussed).

### B. Startup Sequence (3 Terminals Required)

**Terminal 1: Start the Monitoring Dashboard (UDP Receiver)**

This terminal will display live statistics.
(Run in the folder that have the file)
```bash
python monitor.py
```

**Terminal 2: Start the POX Controller**
(Copy the All-in-one_Controller.py file into the /pox/pox/ext folder and go back to /pox/pox to run command)
```bash
cd pox
./pox.py openflow.discovery controller.py
```
**Terminal 3: Start mininet with pre-configured topo**
(Run in the folder that have the file)
```bash
sudo mn --custom multi_router_topo.py --topo mytopo --controller remote --mac
```
