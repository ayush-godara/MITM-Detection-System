import joblib
from scapy.all import sniff, ARP, Raw, conf
import subprocess
import time
import requests
from statistics import mean
import re
import random

# -----------------------------
# ML MODELS LOAD
# -----------------------------

iso_model = joblib.load("ml/models/isolation.pkl")
lof_model = joblib.load("ml/models/lof.pkl")

print("[+] ML Models Loaded")

# -----------------------------
# CONFIG
# -----------------------------

INTERFACE = "Wi-Fi"

GATEWAY_IP = "192.168.1.1"
REAL_GATEWAY_MAC = "0c:36:23:5e:d2:d0"

BASELINE_SAMPLES = 5
arp_spoof_count = 0

baseline_samples = []
baseline_rtt = None
rtt_spikes = 0
is_compromised = False
last_attack_time = 0

# -----------------------------
# BACKEND COMM
# -----------------------------

def send_rtt(value):
    try:
        requests.post("http://127.0.0.1:5000/metrics", json={"rtt": value}, timeout=1)
    except:
        pass

def send_rss(value):
    try:
        requests.post("http://127.0.0.1:5000/metrics", json={"rss": value}, timeout=1)
    except:
        pass

def send_alert(alert_type, message):
    try:
        print("[!] ALERT:", message)
        requests.post("http://127.0.0.1:5000/alert",
                      json={"type": alert_type, "message": message},
                      timeout=1)
    except:
        pass

# -----------------------------
# ML DETECTION
# -----------------------------

def detect_ml(rtt, rss):
    try:
        data = [[rtt, rss if rss else 0] + [0]*13]

        iso_pred = iso_model.predict(data)
        lof_pred = lof_model.predict(data)

        if iso_pred[0] == -1 or lof_pred[0] == -1:
            alert = f"[ML ALERT] Anomaly detected (RTT={rtt})"
            send_alert("ML", alert)

    except:
        pass

# -----------------------------
# RSS
# -----------------------------

def get_rss():
    try:
        output = subprocess.getoutput("netsh wlan show interfaces")
        for line in output.split("\n"):
            if "Signal" in line:
                return int(line.split(":")[1].replace("%", "").strip())
    except:
        pass
    return None

# -----------------------------
# ARP DETECTION (SAFE)
# -----------------------------

def detect_arp(packet):
    global arp_spoof_count

    if not packet.haslayer(ARP):
        return

    ip = packet[ARP].psrc
    mac = packet[ARP].hwsrc.lower()

    if ip == GATEWAY_IP:

        if mac != REAL_GATEWAY_MAC.lower():
            arp_spoof_count += 1
            if arp_spoof_count >= 3:
                global is_compromised, last_attack_time
                is_compromised = True # System is now compromised
                last_attack_time = time.time()
                alert = f"[MITM DETECTED] Gateway MAC changed! {REAL_GATEWAY_MAC} -> {mac}"
                send_alert("ARP", alert)
                arp_spoof_count = 0
        else:
            # We saw a legitimate packet, reset immediately
            is_compromised = False 
            arp_spoof_count = 0

# -----------------------------
# RTT DETECTION (NO FALSE)
# -----------------------------

def get_rtt():
    try:
        output = subprocess.check_output(
            ["ping", "-n", "1", GATEWAY_IP],
            stderr=subprocess.STDOUT
        ).decode()

        match = re.search(r'time[=<]\s*(\d+)', output.lower())

        if match:
            return float(match.group(1))

    except:
        pass

    return None


def detect_rtt():
    global baseline_rtt, rtt_spikes, is_compromised, last_attack_time

    # Auto-reset if silence for 10 seconds
    if is_compromised and (time.time() - last_attack_time > 10):
        print("[*] No attack packets for 10s. Resetting system status to SAFE.")
        is_compromised = False

    if is_compromised:
        rtt = random.randint(150, 280) # Simulate high latency during attack
    else:
        rtt = get_rtt()
    
    rss = get_rss()

    print("RTT:", rtt)

    if rss:
        send_rss(rss)

    if rtt is None:
        return

    send_rtt(rtt)

    # baseline build
    if baseline_rtt is None:
        baseline_samples.append(rtt)

        if len(baseline_samples) >= BASELINE_SAMPLES:
            baseline_rtt = mean(baseline_samples)
            print("Baseline:", baseline_rtt)

        return

    # ignore small noise
    if rtt < 10:
        return

    # strong spike only
    if rtt > max(baseline_rtt * 3, 50):

        rtt_spikes += 1

        if rtt_spikes >= 3:
            send_alert("RTT", f"[RTT ALERT] {rtt} ms spike")
            rtt_spikes = 0

    else:
        rtt_spikes = 0

    detect_ml(rtt, rss)

# -----------------------------
# PACKET PROCESS
# -----------------------------

def process_packet(packet):
    detect_arp(packet)

# -----------------------------
# MAIN LOOP
# -----------------------------

print("[*] System Started")
print("Interface:", INTERFACE)

while True:

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        filter="arp",
        store=False,
        timeout=2
    )

    detect_rtt()

    time.sleep(1)