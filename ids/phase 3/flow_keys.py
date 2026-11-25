"""Flow keys: directional 5-tuple, canonical (bidirectional) key, client guess."""

from typing import Any

from flow_constants import ICMP_REPLY_TYPES, TCP_ACK, TCP_SYN


DirectionalKey = tuple[Any, Any, Any, Any, Any]
Endpoint = tuple[Any, Any]
CanonicalKey = tuple[Endpoint, Endpoint, Any]


def packet_flow_key(packet) -> DirectionalKey:
    """Return the directional 5-tuple for a decoded packet.

    ICMP has no ports, so the echo identifier is used in both port slots:
    two ping sessions between the same hosts become two flows.
    """
    src_port = packet.src_port
    dst_port = packet.dst_port
    if packet.ip_protocol == "ICMP":
        identifier = getattr(packet, "icmp_identifier", None)
        if identifier is not None:
            src_port = dst_port = identifier
    return (
        packet.src_ip,
        src_port,
        packet.dst_ip,
        dst_port,
        packet.ip_protocol,
    )


def _endpoint_sort_key(endpoint: Endpoint) -> tuple[str, int]:
    ip, port = endpoint
    return str(ip), -1 if port is None else port


def canonical_flow_key(flow_key: DirectionalKey) -> CanonicalKey:
    """Normalize both directions of one connection to one lookup key."""
    source = (flow_key[0], flow_key[1])
    destination = (flow_key[2], flow_key[3])
    first, second = sorted((source, destination), key=_endpoint_sort_key)
    return first, second, flow_key[4]


def guess_client(packet, flow_key: DirectionalKey) -> tuple[Endpoint, Endpoint]:
    """Return (client, server) from the first packet seen for a flow."""
    source = (flow_key[0], flow_key[1])
    destination = (flow_key[2], flow_key[3])
    protocol = flow_key[4]

    if protocol == "TCP":
        flags = getattr(packet, "tcp_flags", None)
        if flags is not None and flags & TCP_SYN:
            # SYN comes from the client, SYN-ACK comes from the server.
            if flags & TCP_ACK:
                return destination, source
            return source, destination
    elif protocol == "ICMP":
        if getattr(packet, "icmp_type", None) in ICMP_REPLY_TYPES:
            return destination, source
        return source, destination

    # No handshake seen: servers usually listen on the lower port
    # (80, 443, 3000...) while clients use high ephemeral ports.
    src_port, dst_port = flow_key[1], flow_key[3]
    if src_port is not None and dst_port is not None and src_port < dst_port:
        return destination, source
    return source, destination
