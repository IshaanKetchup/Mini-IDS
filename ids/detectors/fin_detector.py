# fin_detector.py
from scapy.layers.inet import TCP, IP
from datetime import datetime

class FinScanDetector:
    def __init__(self, blacklist, threshold=10):
        self.threshold = threshold
        self.blacklist = blacklist
        self.fin_counts = {}

    def process_packet(self, pkt):
        if not pkt.haslayer(TCP):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]

        if tcp.flags == "F":
            src = ip.src
            self.fin_counts[src] = self.fin_counts.get(src, 0) + 1

            if self.fin_counts[src] >= self.threshold:
                self.blacklist.add(ip.src)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] [ALERT] FIN scan detected from {src}")
