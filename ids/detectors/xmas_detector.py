# xmas_detector.py
from scapy.layers.inet import TCP, IP
from logger import report_alert

class XmasScanDetector:
    def __init__(self, blacklist, threshold=10):
        self.threshold = threshold
        self.blacklist = blacklist
        self.xmas_counts = {}

    def process_packet(self, pkt):
        if not pkt.haslayer(TCP):
            return
        if not pkt.haslayer(IP):
            return
        if not pkt.haslayer(TCP):
            return
        ip = pkt[IP]
        tcp = pkt[TCP]

        if tcp.flags == 0x29:  # FIN+PSH+URG
            src = ip.src
            self.xmas_counts[src] = self.xmas_counts.get(src, 0) + 1

            if self.xmas_counts[src] >= self.threshold:
                self.blacklist.add(ip.src)
                message = f"XMAS scan detected from {src}"
                report_alert(
                    event_type="XMAS",
                    src_ip=src,
                    message=message,
                    severity="high",
                    detection_reason="Repeated TCP packets with FIN+PSH+URG flags",
                    metadata={"threshold": self.threshold, "count": self.xmas_counts[src]}
                )
