# 🧠 AI-Driven Intrusion Detection System (IDS)

## 📖 Overview
A custom-built, Python-based Intrusion Detection System (IDS) that bypasses the OS network stack to capture raw packets mid-air. It utilizes bitwise header slicing, event deduplication, and an integrated cloud-based LLM (Generative AI) to analyze network telemetry and flag unencrypted credential leaks in real-time.

## 🏗️ Architecture Flow
1. **Raw Socket Binding:** Escalates privileges to bind to the Network Interface Card (NIC) in promiscuous mode.
2. **Binary Parsing:** Slices 20-byte IP envelopes and variable-length TCP headers to extract raw payloads.
3. **Pre-Filter Engine:** Utilizes keyword heuristics to prevent API rate-limiting and filter out background OS telemetry.
4. **AI Analysis:** Transmits suspicious UTF-8 payloads to an LLM via API for automated threat classification.
5. **Dual-Tier SIEM Logging:** Separates generic network noise (`intercepts.txt`) from actionable, atomic threat intelligence (`vulnerabilities.txt`).

## ⚙️ Core Engineering Concepts Demonstrated
* `socket` library hardware manipulation (AF_INET, SOCK_RAW).
* Bitwise math for TCP/IP header extraction.
* Asynchronous/Atomic Forensic Logging.
* Secure Environment Variable (`.env`) management.

## 🛡️ Threat Model & Security Policy
* **Privilege Escalation:** This script requires `Administrator` (Windows) or `root` (Linux) privileges to open raw sockets. Running this script exposes the host to potential risks if the script is hijacked.
* **API Security:** The AI integration requires an active API key. **Never commit your `.env` file to version control.**

## 🚀 Quick Start
```bash
# 1. Clone the repository
git clone [https://github.com/YourUsername/DevSecOps-Python-Tools.git](https://github.com/YourUsername/DevSecOps-Python-Tools.git)

# 2. Navigate to the IDS module
cd AI-Intrusion-Detection

# 3. Install dependencies
pip install python-dotenv google-generativeai

# 4. Create your secure environment file
echo "GEMINI_API_KEY=your_key_here" > .env

# 5. Execute with elevated privileges
sudo python sniffer.py
