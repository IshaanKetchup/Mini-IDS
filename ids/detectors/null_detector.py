# null_detector.py
from scapy.layers.inet import TCP, IP
from logger import report_alert

class NullScanDetector:
    def __init__(self, blacklist, threshold=10):
        self.threshold = threshold
        self.blacklist = blacklist
        self.null_counts = {}

    def process_packet(self, pkt):
        if not pkt.haslayer(TCP):
            return
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        tcp = pkt[TCP]

        if tcp.flags == 0:
            src = ip.src
            self.null_counts[src] = self.null_counts.get(src, 0) + 1

            if self.null_counts[src] >= self.threshold:
                self.blacklist.add(ip.src)
                message = f"NULL scan detected from {src}"
                report_alert(
                    event_type="NULL",
                    src_ip=src,
                    message=message,
                    severity="high",
                    detection_reason="Repeated TCP packets with no flags set",
                    metadata={"threshold": self.threshold, "count": self.null_counts[src]}
                )
