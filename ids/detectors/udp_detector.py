# udp_detector.py
from scapy.layers.inet import UDP, IP
from logger import report_alert

class UdpScanDetector:
    def __init__(self, threshold=10):
        self.threshold = threshold
        self.udp_ports = {}

    def process_packet(self, pkt):
        if not pkt.haslayer(UDP):
            return
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        udp = pkt[UDP]

        src = ip.src
        dport = udp.dport

        if src not in self.udp_ports:
            self.udp_ports[src] = set()

        self.udp_ports[src].add(dport)

        if len(self.udp_ports[src]) >= self.threshold:
            message = f"UDP scan detected from {src}"
            report_alert(
                event_type="UDP",
                src_ip=src,
                message=message,
                severity="medium",
                detection_reason="Many distinct UDP destination ports from one source",
                metadata={"threshold": self.threshold, "port_count": len(self.udp_ports[src])}
            )
