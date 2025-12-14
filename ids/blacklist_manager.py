import threading

class BlacklistManager:
    def __init__(self, filepath="blacklist.txt"):
        self.filepath = filepath
        self.lock = threading.Lock()
        self.blacklisted = set()
        self._load()

    def _load(self):
        try:
            # Reload file into memory (replace current in-memory set)
            new_set = set()
            with open(self.filepath, "r") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        new_set.add(ip)
            self.blacklisted = new_set
        except FileNotFoundError:
            pass

    def add(self, ip):
        """
        Adds the IP to the blacklist if not already present.
        Does not prevent the IDS from processing packets from this IP.
        """
        with self.lock:
            # Refresh from file first so we don't have stale in-memory state
            # (e.g., UI removed the IP from file but this instance still had it cached).
            self._load()
            if ip not in self.blacklisted:
                self.blacklisted.add(ip)
                with open(self.filepath, "a") as f:
                    f.write(ip + "\n")

    def get_all(self):
        """
        Returns a copy of all blacklisted IPs.
        """
        with self.lock:
            return set(self.blacklisted)
