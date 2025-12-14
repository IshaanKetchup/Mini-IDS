from scapy.all import sniff
from typing import Callable

class PacketCapture:
    def __init__(self, callback: Callable):
        self.callback = callback

    def start(self, interface="eth0"):
        sniff(
            iface=interface,
            prn=self.callback,
            store=False,
            filter="tcp"
        )
