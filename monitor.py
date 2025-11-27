# -*- coding: utf-8 -*-
# monitor.py
import socket
import sys
import time

# Cấu hình Dashboard
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 6666

def start_server():
    # Tạo UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        sock.bind((LISTEN_IP, LISTEN_PORT))
    except socket.error as e:
        print("Error: Cannot bind to port %s. Is another monitor running?" % LISTEN_PORT)
        sys.exit(1)

    print("=================================================")
    print("   TRAFFIC MONITOR DASHBOARD (UDP Listener)      ")
    print("=================================================")
    print("Waiting for data from Controller at %s:%s..." % (LISTEN_IP, LISTEN_PORT))
    print("Press Ctrl+C to exit.")
    print("-------------------------------------------------")

    try:
        while True:
            # Nhận dữ liệu (tối đa 4096 bytes)
            data, addr = sock.recvfrom(4096)
            message = data.decode('utf-8')
            
            # In ra màn hình với thời gian thực
            current_time = time.strftime("%H:%M:%S")
            print("[%s] %s" % (current_time, message))
            
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
    finally:
        sock.close()

if __name__ == "__main__":
    start_server()
