class IPReputation:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.blocklist = set(config.get("blocklist", []))
        self.allowlist = set(config.get("allowlist", ["127.0.0.1", "::1"]))

    def is_allowed(self, ip: str) -> bool:
        if not self.enabled:
            return True
        if ip in self.allowlist:
            return True
        if ip in self.blocklist:
            return False
        return True

    def is_allowlisted(self, ip: str) -> bool:
        if not self.enabled:
            return False
        return ip in self.allowlist

    def block_ip(self, ip: str):
        self.blocklist.add(ip)

    def unblock_ip(self, ip: str):
        self.blocklist.discard(ip)

    def allow_ip(self, ip: str):
        self.allowlist.add(ip)

    def remove_allow_ip(self, ip: str):
        self.allowlist.discard(ip)

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "blocked_count": len(self.blocklist),
            "allowed_count": len(self.allowlist),
        }
