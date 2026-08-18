"""Shared helpers used across SentinelShield."""


def get_client_ip_from_headers(headers, fallback="127.0.0.1"):
    """Extract the real client IP from proxy forwarding headers.

    Checks ``X-Forwarded-For`` (first entry) then ``X-Real-IP`` before
    falling back to *fallback*.  ``headers`` must be a mapping whose
    keys are **lower-case** (e.g. ``{"x-forwarded-for": "..."}``).
    """
    xff = headers.get("x-forwarded-for")
    if xff:
        # X-Forwarded-For may contain a comma-separated list;
        # the first entry is the original client.
        return xff.split(",")[0].strip()

    xri = headers.get("x-real-ip")
    if xri:
        return xri.strip()

    return fallback
