"""Packet abstraction shared with later IDS phases."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Packet:
    timestamp: float
    capture_length: Optional[int] = None
    wire_length: Optional[int] = None

    src_mac: str = "unknown"
    dst_mac: str = "unknown"
    ethertype: Optional[int] = None

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_protocol: Optional[str] = None
    ip_protocol_number: Optional[int] = None
    ip_ttl: Optional[int] = None
    ip_id: Optional[int] = None
    ip_header_length: Optional[int] = None
    ip_total_length: Optional[int] = None
    ip_checksum: Optional[int] = None
    fragment_offset: int = 0
    fragment_offset_bytes: int = 0
    more_fragments: bool = False
    dont_fragment: bool = False
    ip_options: bytes = field(default_factory=bytes)
    ip_fragment_key: Optional[tuple] = None
    # Set by the Phase 4 IP defragmenter when this packet was rebuilt from fragments.
    reassembled_fragments: int = 0
    defrag_anomalies: tuple = ()

    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_flags: Optional[int] = None
    tcp_flags_text: Optional[str] = None
    tcp_window: Optional[int] = None
    tcp_header_length: Optional[int] = None
    tcp_checksum: Optional[int] = None
    tcp_urgent_pointer: Optional[int] = None
    tcp_options: bytes = field(default_factory=bytes)

    udp_length: Optional[int] = None
    udp_checksum: Optional[int] = None

    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    icmp_checksum: Optional[int] = None
    icmp_identifier: Optional[int] = None
    icmp_sequence: Optional[int] = None

    payload: bytes = field(default_factory=bytes)
    flow_key: Optional[tuple] = None

    def payload_length(self):
        return len(self.payload)

    def is_ip_fragment(self):
        return self.fragment_offset != 0 or self.more_fragments

    def is_first_fragment(self):
        return self.fragment_offset == 0

    def summary(self):
        return (
            f"{self.ip_protocol or 'NON-IP'} "
            f"{self.src_ip or '-'}:{self.src_port or '-'} -> "
            f"{self.dst_ip or '-'}:{self.dst_port or '-'} "
            f"payload={len(self.payload)}"
        )
