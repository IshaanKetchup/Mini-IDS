# udp_detector.py
from scapy.layers.inet import UDP, IP

class UdpScanDetector:
    def __init__(self, threshold=10):
        self.threshold = threshold
        self.udp_ports = {}

    def process_packet(self, pkt):
        if not pkt.haslayer(UDP):
            return

        ip = pkt[IP]
        udp = pkt[UDP]

        src = ip.src
        dport = udp.dport

        if src not in self.udp_ports:
            self.udp_ports[src] = set()

        self.udp_ports[src].add(dport)

        if len(self.udp_ports[src]) >= self.threshold:
            print(f"[ALERT] UDP scan detected from {src}")
