# fin_detector.py
from scapy.layers.inet import TCP, IP
from logger import report_alert

class FinScanDetector:
    def __init__(self, blacklist, threshold=10):
        self.threshold = threshold
        self.blacklist = blacklist
        self.fin_counts = {}

    def process_packet(self, pkt):
        if not pkt.haslayer(TCP):
            return
        if not pkt.haslayer(IP):
            return
        if not pkt.haslayer(TCP):
            return
        ip = pkt[IP]
        tcp = pkt[TCP]

        if tcp.flags == "F":
            src = ip.src
            self.fin_counts[src] = self.fin_counts.get(src, 0) + 1

            if self.fin_counts[src] >= self.threshold:
                self.blacklist.add(ip.src)
                message = f"FIN scan detected from {src}"
                report_alert(
                    event_type="FIN",
                    src_ip=src,
                    message=message,
                    severity="high",
                    detection_reason="Repeated FIN-only TCP packets",
                    metadata={"threshold": self.threshold, "count": self.fin_counts[src]}
                )
