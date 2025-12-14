# arp_spoof_detector.py
from scapy.layers.l2 import ARP
from datetime import datetime

class ArpSpoofDetector:
    def __init__(self, blacklist):
        self.arp_table = {}
        self.blacklist = blacklist

    def process_packet(self, pkt):
        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]
        ip = arp.psrc
        mac = arp.hwsrc

        if ip not in self.arp_table:
            self.arp_table[ip] = mac
            return

        if self.arp_table[ip] != mac:
            self.blacklist.add(ip.src)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] [ALERT] ARP spoofing detected: {ip} is being claimed by {mac} (previous {self.arp_table[ip]})")
            self.arp_table[ip] = mac  # update so you don't spam alerts
