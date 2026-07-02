from scapy.layers.inet import TCP, IP
from logger import report_alert

class SynScanDetector:
    def __init__(self, state_store, blacklist, threshold=10):
        self.blacklist = blacklist
        self.state = state_store
        self.threshold = threshold

    def process_packet(self, pkt):
        # Bail early if the packet isn't IP or isn't TCP
        if not pkt.haslayer(IP):
            return
        if not pkt.haslayer(TCP):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]

        if (tcp.flags & 0x02) and not (tcp.flags & 0x10):
            self.state.record_syn(ip.src, tcp.dport)
            syn_list = self.state.get_recent_syns(ip.src)
            #print(f"SYN from {ip.src} to port {tcp.dport}")

            unique_ports = {p for (_, p) in syn_list}
            #print(f"DEBUG unique ports from {ip.src}: {len(unique_ports)}")

            if len(unique_ports) >= self.threshold:
                        self.blacklist.add(ip.src)
                        message = f"SYN scan detected from {ip.src}"
                        report_alert(
                            event_type="SYN",
                            src_ip=ip.src,
                            message=message,
                            severity="high",
                            detection_reason="Repeated SYN packets across many destination ports",
                            metadata={"threshold": self.threshold, "unique_ports": len(unique_ports)}
                        )