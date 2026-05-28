import socket
import concurrent.futures
import time
import sys

if len(sys.argv) != 2:
    print("[-] ERROR: Invalid Target.")
    print("[*] USAGE: python payload.py <target_ip>")
    sys.exit()
target_ip = sys.argv[1]

def scan_port(port_num):
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    scanner.settimeout(0.1)
    result = scanner.connect_ex((target_ip, port_num))
    if result == 0:
        print(f"[ALERT] Port {port_num} in open")
    else:
        pass
    scanner.close()

start_time = time.perf_counter()
print("[*] Initiating Multithreaded Scan...")
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    executor.map(scan_port, range(1, 1025))
print("[*] Scan Complete!")
end_time = time.perf_counter()
print(f"Time taken to complete scan: {end_time - start_time:.2f} seconds")
