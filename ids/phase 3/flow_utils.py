"""Small helpers that read attributes of a decoded packet."""


def packet_size(packet) -> int:
    """Return the IP-layer size of a packet, falling back to capture sizes."""
    for name in ("ip_total_length", "wire_length", "capture_length"):
        value = getattr(packet, name, None)
        if value:
            return value
    return len(getattr(packet, "payload", b"") or b"")


def is_non_first_fragment(packet) -> bool:
    """A non-first IP fragment has no transport header (and no ports)."""
    return bool(getattr(packet, "fragment_offset", 0))
