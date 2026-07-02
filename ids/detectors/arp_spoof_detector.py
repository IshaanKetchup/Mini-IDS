# arp_spoof_detector.py
from scapy.layers.l2 import ARP
from logger import report_alert

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
            self.blacklist.add(ip)
            message = f"ARP spoofing detected: {ip} is being claimed by {mac} (previous {self.arp_table[ip]})"
            report_alert(
                event_type="ARP",
                src_ip=ip,
                message=message,
                severity="high",
                detection_reason="ARP reply conflict for same IP with different MAC address",
                metadata={"previous_mac": self.arp_table[ip], "current_mac": mac}
            )
            self.arp_table[ip] = mac  # update so you don't spam alerts
