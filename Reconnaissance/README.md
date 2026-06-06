# 👻 Ghost Scanner: Attack Surface Mapper

## 📖 Overview
Developed as part of foundational B.Tech DevSecOps research to understand network perimeter defense, Ghost Scanner is a lightweight, multi-threaded Python utility designed for internal network mapping and service enumeration. It allows security engineers to audit local infrastructure, identify unauthorized open ports, and detect "Shadow IT" running on corporate networks.

## ⚠️ Academic & Legal Disclaimer
**STRICTLY FOR AUTHORIZED INFRASTRUCTURE AUDITS.** Network scanning without explicit administrative consent is illegal and violates standard corporate security policies. This tool is engineered solely for academic research, local wargame environments, and authorized penetration testing engagements. Do not point this utility at external IP addresses or third-party networks. 

## 🏗️ Technical Architecture
* **Multi-Threaded Execution:** Utilizes Python's `threading` and `concurrent.futures` modules to execute concurrent socket connection attempts, drastically reducing scan times across large IP subnets.
* **TCP Socket Interrogation:** Executes standard TCP Connect sweeps to identify active listeners and open states on target host ports.
* **Banner Grabbing (Service Enumeration):** Extracts initial application-layer handshakes to identify the exact service and software version running on an exposed port (e.g., OpenSSH 8.2, Apache 2.4).
* **Graceful Exception Handling:** Implements precise socket timeout controls to prevent thread hanging on dropped packets or severely rate-limited firewalls.

## 🛡️ Defensive Application (Blue Team)
While port scanners are traditionally offensive tools, Ghost Scanner is built to support **Attack Surface Management (ASM)**. 
* **Rogue Asset Detection:** Identifying forgotten test servers or misconfigured databases spun up by internal developers.
* **Firewall Verification:** Proving that edge-firewall Access Control Lists (ACLs) are successfully dropping external traffic to internal-only services (like SMB Port 445 or RDP Port 3389).

## 🚀 Quick Start
```bash
# 1. Clone the repository
git clone [https://github.com/YourUsername/DevSecOps-Python-Tools.git](https://github.com/YourUsername/DevSecOps-Python-Tools.git)

# 2. Navigate to the Reconnaissance module
cd Reconnaissance

# 3. Execute the scanner (Example: Scanning local loopback)
# Note: Adjust the target IP and port range within the script or via CLI arguments as configured.
python ghost_scanner.py --target 127.0.0.1 --ports 1-1024
