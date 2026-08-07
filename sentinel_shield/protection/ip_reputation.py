from typing import List, Optional, Set


class IPReputation:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.blocklist: Set[str] = set(config.get("blocklist", []))
        self.allowlist: Set[str] = set(config.get("allowlist", ["127.0.0.1", "::1"]))

    def is_allowed(self, client_ip: str) -> bool:
        if not self.enabled:
            return True
        if client_ip in self.allowlist:
            return True
        if client_ip in self.blocklist:
            return False
        return True

    def is_allowlisted(self, client_ip: str) -> bool:
        if not self.enabled:
            return False
        return client_ip in self.allowlist

    def block_ip(self, client_ip: str):
        self.blocklist.add(client_ip)

    def unblock_ip(self, client_ip: str):
        self.blocklist.discard(client_ip)

    def allow_ip(self, client_ip: str):
        self.allowlist.add(client_ip)

    def remove_allow_ip(self, client_ip: str):
        self.allowlist.discard(client_ip)

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "blocked_count": len(self.blocklist),
            "allowed_count": len(self.allowlist),
        }
