from scapy.all import sniff, ARP, Raw, conf
import subprocess
import time
import requests
from statistics import mean
import re

# -----------------------------
# CONFIG (UPDATED ✅)
# -----------------------------

INTERFACE = conf.iface

GATEWAY_IP = "10.118.210.215"
REAL_GATEWAY_MAC = "a6:42:43:11:23:7b"

RTT_THRESHOLD_MULTIPLIER = 2.0
BASELINE_SAMPLES = 5
SPIKE_CONFIRMATION = 3

arp_table = {}

baseline_samples = []
baseline_rtt = None
rtt_spikes = 0

last_payload_alert = 0
PAYLOAD_COOLDOWN = 10

# -----------------------------
# DASHBOARD COMMUNICATION
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
        requests.post(
            "http://127.0.0.1:5000/alert",
            json={"type": alert_type, "message": message},
            timeout=1
        )
    except:
        pass

def log_alert(message):
    with open("alerts.txt", "a") as f:
        f.write(message + "\n")

# -----------------------------
# RSS SIGNAL
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
# ARP DETECTION (FIXED ✅)
# -----------------------------

def detect_arp(packet):

    if not packet.haslayer(ARP):
        return

    ip = packet[ARP].psrc
    mac = packet[ARP].hwsrc.lower()

    print("ARP:", ip, mac)

    # 🔥 Gateway spoof detection
    if ip == GATEWAY_IP and mac != REAL_GATEWAY_MAC.lower():
        alert = f"[MITM DETECTED] Gateway MAC changed! {REAL_GATEWAY_MAC} -> {mac}"
        print(alert)
        log_alert(alert)
        send_alert("ARP", alert)

    # 🔥 General ARP change
    if ip in arp_table and arp_table[ip] != mac:
        alert = f"[ARP CHANGE] {ip} {arp_table[ip]} -> {mac}"
        print(alert)
        log_alert(alert)
        send_alert("ARP", alert)

    arp_table[ip] = mac

# -----------------------------
# PAYLOAD DETECTION
# -----------------------------

def inspect_payload(packet):

    global last_payload_alert

    if not packet.haslayer(Raw):
        return

    try:
        data = packet[Raw].load.decode(errors="ignore").lower()
    except:
        return

    keywords = ["password", "login", "token", "cookie"]

    for word in keywords:
        if word in data:

            if time.time() - last_payload_alert < PAYLOAD_COOLDOWN:
                return

            alert = f"[PAYLOAD ALERT] {word} detected"
            print(alert)
            log_alert(alert)
            send_alert("PAYLOAD", alert)

            last_payload_alert = time.time()
            break

# -----------------------------
# RTT MONITOR
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

    global baseline_rtt, rtt_spikes

    rtt = get_rtt()
    rss = get_rss()

    print("RTT:", rtt)

    if rss is not None:
        send_rss(rss)

    if rtt is None:
        return

    send_rtt(rtt)

    if baseline_rtt is None:

        baseline_samples.append(rtt)

        if len(baseline_samples) >= BASELINE_SAMPLES:
            baseline_rtt = mean(baseline_samples)
            print("✅ Baseline RTT:", baseline_rtt)

        return

    if rtt > baseline_rtt * RTT_THRESHOLD_MULTIPLIER:

        rtt_spikes += 1

        if rtt_spikes >= SPIKE_CONFIRMATION:
            alert = f"[RTT ALERT] Spike detected: {rtt} ms"
            print(alert)
            log_alert(alert)
            send_alert("RTT", alert)
            rtt_spikes = 0

    else:
        rtt_spikes = 0

# -----------------------------
# PACKET PROCESSOR
# -----------------------------

def process_packet(packet):
    detect_arp(packet)
    inspect_payload(packet)

# -----------------------------
# MAIN LOOP
# -----------------------------

print("🚀 MITM Detection Started...")
print("Interface:", INTERFACE)
print("Gateway:", GATEWAY_IP)
print("Real MAC:", REAL_GATEWAY_MAC)

while True:

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        filter="arp or tcp",
        store=False,
        timeout=2
    )

    detect_rtt()

    time.sleep(1)