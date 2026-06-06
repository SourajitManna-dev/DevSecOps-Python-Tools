import socket
import struct
import os
from dotenv import load_dotenv
import google.generativeai as genai
load_dotenv()
genai.configure(api_key=os.environ["GEMINI_API_KEY"])
model = genai.GenerativeModel('gemini-2.5-flash')

def analyze_log(log_text):
    ai_command = f"""
    You are an automated DevSecOps analyst. Analyze this intercepted network payload. 
    If it is generic background noise, encrypted TLS, or unreadable binary, reply ONLY with 'NOISE'. 
    If it contains plaintext credentials, tracking beacons, or suspicious telemetry, 
    provide a 1-sentence threat flag.
    
    Raw Payload: {log_text}
    """
    try:
        response = model.generate_content(ai_command)
        ai_verdict = response.text.strip()

        
        if "NOISE" not in ai_verdict:
            print("\n" + "!"*55)
            print("[AI THREAT DETECTION FLAG]")
            print(ai_verdict)
            print("!"*55 + "\n")
            with open("vulnerabilities.txt", "a", encoding="utf-8") as threat_file:
                threat_file.write(f"--- [CRITICAL THREAT CAPTURED] ---\n")
                threat_file.write(f"RAW DATA: {log_text}\n\n")
                threat_file.write(f"AI VERDICT: {ai_verdict}\n")
                threat_file.write("=" * 60 + "\n\n")
                 
    except Exception as e:
        print(f"[!] AI Engine Connection Error: {e}")

HOST = "192.168.31.161"

conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
conn.bind((HOST, 0))
conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

conn.settimeout(2.0)

print(f"[*] AI-Driven Sniffer Engine Online. Listening on {HOST}...\n")

try:
    while True:
        try:
            raw_data, addr = conn.recvfrom(65535)
        except socket.timeout:
            continue

        ip_header = raw_data[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        version_ihl = iph[0]
        ihl = version_ihl & 15
        ip_header_length = ihl * 4
        protocol = iph[6]
        
        raw_payload = b''
        
        if protocol == 6:  
            tcp_header_start = ip_header_length
            tcp_header_bytes = raw_data[tcp_header_start : tcp_header_start + 20]
            
            if len(tcp_header_bytes) >= 20:
                data_offset_byte = struct.unpack('!B', tcp_header_bytes[12:13])[0]
                tcp_header_length = (data_offset_byte >> 4) * 4
                
                payload_start = ip_header_length + tcp_header_length
                raw_payload = raw_data[payload_start:]
                
        elif protocol == 17:  
            payload_start = ip_header_length + 8
            raw_payload = raw_data[payload_start:]
        else:
            continue 

        if raw_payload:
            readable_payload = raw_payload.decode('utf-8', errors='ignore').strip()
            clean_payload = " ".join(readable_payload.split())
            
            if clean_payload:
                print(f"L--> [PAYLOAD]: {clean_payload[:80]}")
                with open("intercepts.txt", "a", encoding="utf-8") as f:
                    f.write(f"[PAYLOAD TEXT]: {clean_payload[:80]}\n")                
                
                trigger_words = ["password", "login", "admin", "user", "auth", "token"]
                payload_lower = clean_payload.lower()
                is_suspicious = any(word in payload_lower for word in trigger_words)
                if is_suspicious:
                    print(f"\n[*] THREAT CAPTURED. Evidence locked in vulnerabilities.txt. Querying AI...")
                    analyze_log(clean_payload)

except KeyboardInterrupt:
    print("\n[*] Shutting down engine safely...")
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
