"""
IP reputation keeps two simple lists:

* blocklist - IPs that are never allowed in.
* allowlist - IPs that are always allowed in (bypass every check).

If an IP is in both lists, the allowlist wins because it is checked first.
"""


class IPReputation:
    def __init__(self, config):
        self.enabled = config.get("enabled", True)
        self.blocklist = set(config.get("blocklist", []))
        self.allowlist = set(config.get("allowlist", ["127.0.0.1", "::1"]))

    def is_allowed(self, ip):
        """Return True if the IP may send requests."""
        if not self.enabled:
            return True
        if ip in self.allowlist:
            return True
        if ip in self.blocklist:
            return False
        return True

    def is_allowlisted(self, ip):
        """Return True if the IP bypasses all protection."""
        if not self.enabled:
            return False
        return ip in self.allowlist

    def block_ip(self, ip):
        self.blocklist.add(ip)

    def unblock_ip(self, ip):
        self.blocklist.discard(ip)

    def allow_ip(self, ip):
        self.allowlist.add(ip)

    def remove_allow_ip(self, ip):
        self.allowlist.discard(ip)

    def get_stats(self):
        return {
            "enabled": self.enabled,
            "blocked_count": len(self.blocklist),
            "allowed_count": len(self.allowlist),
        }
