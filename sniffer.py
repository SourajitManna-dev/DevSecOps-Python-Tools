import socket
import os
import struct

HOST = "192.168.31.161"

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sniffer.bind((HOST, 0))

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

sniffer.settimeout(1.0)
print(f"[*] Engine started. Sniffing traffic on {HOST}...\n")
print("[*] Press Ctrl+C to safely shut down.\n")
print("-" * 65)

try:
    while True:
        try:
            raw_data, addr = sniffer.recvfrom(65535)
            
        except socket.timeout:
            continue
        ip_header = raw_data[0:20]
        first_byte = struct.unpack("!B", ip_header[0:1])[0]
        version = first_byte >> 4
        ihl = first_byte & 15

        address_bytes = ip_header[12:20]
        addresses = struct.unpack("!4s4s", address_bytes)
        source_ip = socket.inet_ntoa(addresses[0])
        destination_ip = socket.inet_ntoa(addresses[1])
                
        print(f"IPv{version} Packet | IHL: {ihl} | Source: {source_ip} -> Destination: {destination_ip}")
        
        protocol = struct.unpack('!B', raw_data[9:10])[0]
        ip_header_length = ihl * 4

        if protocol == 6: 
            protocol_name = "TCP"
            tcp_header_start = ip_header_length
            tcp_header_bytes = raw_data[tcp_header_start : tcp_header_start + 20]
            
            if len(tcp_header_bytes) >= 20:
                ports = struct.unpack('!HH', tcp_header_bytes[0:4])
                source_port, dest_port = ports[0], ports[1]
                data_offset_byte = struct.unpack('!B', tcp_header_bytes[12:13])[0]
                tcp_header_length = (data_offset_byte >> 4) * 4
                
                payload_start = ip_header_length + tcp_header_length
                raw_payload = raw_data[payload_start:]

        elif protocol == 17:  
            protocol_name = "UDP"
            port_bytes = raw_data[ip_header_length : ip_header_length + 4]
            
            if len(port_bytes) >= 4:
                ports = struct.unpack('!HH', port_bytes)
                source_port, dest_port = ports[0], ports[1]
                
                payload_start = ip_header_length + 8
                raw_payload = raw_data[payload_start:]
        else:
            protocol_name = None


        if protocol_name:
            print(f"      L--> [{protocol_name}] Source Port: {source_port} -> Dest Port: {dest_port}")
            
            if raw_payload:
                readable_payload = raw_payload.decode('utf-8', errors='ignore').strip()
                clean_payload = " ".join(readable_payload.split())
                
                if clean_payload:
                    
                    print(f"      L--> [PAYLOAD TEXT]: {clean_payload[:80]}")
                
                with open("intercepts.txt", "a", encoding="utf-8") as f:
                        f.write(f"[PAYLOAD TEXT]: {clean_payload[:80]}\n")
            print("-" * 65)
            
except KeyboardInterrupt:
    print("\n\n[*] Ctrl+C detected. Mission aborted.")
    print("[*] Safely disabling Promiscuous Mode...")

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("[*] Engine shut down cleanly.")

