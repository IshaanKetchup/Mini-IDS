# xmas_detector.py
from scapy.layers.inet import TCP, IP
from datetime import datetime

class XmasScanDetector:
    def __init__(self, blacklist, threshold=10):
        self.threshold = threshold
        self.blacklist = blacklist
        self.xmas_counts = {}

    def process_packet(self, pkt):
        if not pkt.haslayer(TCP):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]

        if tcp.flags == 0x29:  # FIN+PSH+URG
            src = ip.src
            self.xmas_counts[src] = self.xmas_counts.get(src, 0) + 1

            if self.xmas_counts[src] >= self.threshold:
                self.blacklist.add(ip.src)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] [ALERT]] XMAS scan detected from {src}")
