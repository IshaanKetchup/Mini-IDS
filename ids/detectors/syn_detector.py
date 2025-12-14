from scapy.layers.inet import TCP, IP
from datetime import datetime

try:
    from frontend.app import alert_store, socketio
    FRONTEND_AVAILABLE = True
except ImportError:
    FRONTEND_AVAILABLE = False

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

        if tcp.flags == "S":
            self.state.record_syn(ip.src, tcp.dport)
            syn_list = self.state.get_recent_syns(ip.src)

            unique_ports = {p for (_, p) in syn_list}

            if len(unique_ports) >= self.threshold:
                        self.blacklist.add(ip.src)
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        message = f"SYN scan detected from {ip.src}"
                        print(f"[{timestamp}] [ALERT] {message}")
                        
                        # Send to frontend via WebSocket
                        if FRONTEND_AVAILABLE:
                            alert_data = {
                                'timestamp': timestamp,
                                'type': 'SYN',
                                'src_ip': ip.src,
                                'message': message
                            }
                            alert_store.add_alert('SYN', ip.src, message)
                            # Also emit directly via socketio
                            socketio.emit('new_alert', alert_data)