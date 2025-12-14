import time
from collections import defaultdict

class StateStore:
    def __init__(self, window_seconds=10):
        self.window = window_seconds
        self.syn_log = defaultdict(list)

    def record_syn(self, src_ip, dst_port):
        now = time.time()
        self.syn_log[src_ip].append((now, dst_port))
        self._cleanup(src_ip)

    def get_recent_syns(self, src_ip):
        self._cleanup(src_ip)
        return self.syn_log[src_ip]

    def _cleanup(self, src_ip):
        now = time.time()
        self.syn_log[src_ip] = [
            (t, p) for (t, p) in self.syn_log[src_ip]
            if now - t <= self.window
        ]
