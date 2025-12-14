# null_detector.py
from scapy.layers.inet import TCP, IP
from datetime import datetime

class NullScanDetector:
    def __init__(self, blacklist, threshold=10):
        self.threshold = threshold
        self.blacklist = blacklist
        self.null_counts = {}

    def process_packet(self, pkt):
        if not pkt.haslayer(TCP):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]

        if tcp.flags == 0:
            src = ip.src
            self.null_counts[src] = self.null_counts.get(src, 0) + 1

            if self.null_counts[src] >= self.threshold:
                self.blacklist.add(ip.src)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] [ALERT] NULL scan detected from {src}")
