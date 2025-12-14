from .packet_capture import PacketCapture
from .detectors.syn_detector import SynScanDetector
from .state_store import StateStore
from .detectors.fin_detector import FinScanDetector
from .detectors.null_detector import NullScanDetector
from .detectors.xmas_detector import XmasScanDetector
from .detectors.udp_detector import UdpScanDetector
from .detectors.arp_spoof_detector import ArpSpoofDetector
from scapy.layers.inet import TCP, IP
from .blacklist_manager import BlacklistManager



class IDS:
    def __init__(self):
        self.state = StateStore(window_seconds=10)
        self.blacklist = BlacklistManager()  

        self.detectors = [
            SynScanDetector(self.state, self.blacklist),
            FinScanDetector(self.blacklist),
            NullScanDetector(self.blacklist),
            XmasScanDetector(self.blacklist),
            UdpScanDetector(self.blacklist),
            ArpSpoofDetector(self.blacklist)
        ]

    def packet_handler(self, pkt):
        ip = pkt[IP].src if IP in pkt else None

        # process packet through all detectors
        for det in self.detectors:
            det.process_packet(pkt)

    def run(self, interface="eth0"):
        print(f"Listening on {interface}")
        capturer = PacketCapture(self.packet_handler)
        capturer.start(interface=interface)

if __name__ == "__main__":
    ids = IDS()
    print("IDS Running")
    ids.run(interface="\\Device\\NPF_{2C8A903D-15B6-49B6-86D8-6992D5571166}")
    #ids.run(interface="\\Device\\NPF_{AB7CC625-27EC-4F9B-B653-4FA111723C10}")

