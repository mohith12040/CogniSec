# CogniSec: Cognitive Deception Network and Intrusion Manipulation System

## Intelligent Cyber Attack Simulation & Threat Detection Platform

COGNISEC is an advanced cybersecurity simulation and deception platform designed to emulate real-world cyber attacks, monitor malicious behavior, and visualize security events in real time.

The project combines:
- Attack simulation
- Honeypot deception systems
- Behavioral anomaly detection
- Real-time monitoring dashboards
- Machine learning–based threat analysis

Built using Python, Flask, and security-focused network logic.

---

# 🚀 Features

## 🔥 Attack Simulation Engine
Simulates multiple real-world cyber attacks including:

- Port Scanning
- Stealth SYN Scans
- SSH Brute Force
- FTP Credential Attacks
- Web Vulnerability Scanning
- SMB / Windows Exploit Attempts
- Database Attacks
- High-Entropy Payload Injection
- Reconnaissance Activities

---

## 🛡️ Threat Detection System

CogniSec includes:
- Behavioral anomaly detection
- Isolation Forest ML scoring
- Suspicious traffic analysis
- Entropy-based payload inspection
- Failed authentication tracking
- SYN flood pattern detection

---

## 🎭 Honeypot & Deception Layer

The platform maps hundreds of service ports to simulated honeypots including:

- SSH
- FTP
- HTTP/HTTPS
- SMTP
- MySQL
- MSSQL
- Oracle
- SMB
- RDP
- Telnet

This allows realistic attacker interaction and deception monitoring.

---

# 📊 Real-Time Dashboard

Interactive Flask-based cyber dashboard featuring:

- Live attack monitoring
- Threat severity visualization
- Traffic analytics
- Attack timelines
- Security telemetry
- Real-time event streaming
- Cyberpunk-inspired SOC UI

---

# 🧠 Machine Learning Integration

CogniSec uses:
- Isolation Forest anomaly detection
- Behavioral traffic analysis
- Pattern deviation scoring

to identify suspicious activity automatically.

---

# 🛠️ Technologies Used

- Python
- Flask
- Scikit-learn
- JavaScript
- HTML/CSS
- Chart.js
- Linux
- Threading
- REST APIs
- SSE (Server-Sent Events)

---

# 📂 Project Structure

```bash
CogniSec/
│
├── app.py              # Flask application & dashboard
├── engine.py           # Detection engine & honeypot system
├── attacker.py         # Attack simulator CLI
└── README.md
```

# ⚙️ Installation Guide
## 1. Clone the Repository
```bash
git clone https://github.com/mohith12040/CogniSec.git
```
⸻

## 2. Move into the Project Directory
```bash
cd CogniSec
```
⸻

## 3. Install Dependencies
```bash
pip install -r requirements.txt
```
⸻

## 4. Start the Flask Server
```bash
python3 app.py
```
⸻

## 5. Expected Output

You should see output similar to:

╔══════════════════════════════════════════════════════╗
║  COGNISEC — Cognitive Deception Engine              ║
╠══════════════════════════════════════════════════════╣
║  Overview   ->  http://localhost:5000/              ║
║  Traffic    ->  http://localhost:5000/traffic       ║
║  Honeypots  ->  http://localhost:5000/honeypots     ║
║  Attackers  ->  http://localhost:5000/attackers     ║
║  Attack CLI ->  python3 attacker.py                 ║
╚══════════════════════════════════════════════════════╝

⸻

## 6. Open the Dashboard

Open your browser and visit:

http://localhost:5000

⸻

## 7. Run the Attack Simulator

After starting the server, open a new terminal tab in the same project directory and run:

python3 attacker.py

This will simulate multiple cyber attack patterns and display them live inside the CogniSec dashboard.

⸻

## 🌐 Access Overview Pages

You can access different dashboard sections using:

http://localhost:5000/
http://localhost:5000/traffic
http://localhost:5000/honeypots
http://localhost:5000/attackers
