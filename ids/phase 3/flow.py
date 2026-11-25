"""State and statistics of one bidirectional flow."""

from dataclasses import dataclass, field
from typing import Any, Optional

from flow_constants import (
    STATUS_ACTIVE,
    TCP_ACK,
    TCP_CLOSED,
    TCP_CLOSING,
    TCP_ESTABLISHED,
    TCP_FIN,
    TCP_FIN_WAIT,
    TCP_FLAG_NAMES,
    TCP_MIDSTREAM,
    TCP_NONE,
    TCP_RST,
    TCP_SYN,
    TCP_SYN_RECEIVED,
    TCP_SYN_SENT,
)
from flow_keys import CanonicalKey, Endpoint


def _format_endpoint(endpoint: Endpoint, protocol: Any) -> str:
    ip, port = endpoint
    if port is None:
        return str(ip)
    if protocol == "ICMP":
        return f"{ip}[id={port}]"
    return f"{ip}:{port}"


@dataclass
class Flow:
    """State and statistics for one bidirectional network flow.

    "fwd" means client -> server, "bwd" means server -> client.
    """

    key: CanonicalKey
    protocol: Any
    client: Endpoint
    server: Endpoint
    first_seen: float
    last_seen: float
    is_continuation: bool = False

    packet_count: int = 0
    byte_count: int = 0
    payload_byte_count: int = 0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    fwd_payload_bytes: int = 0
    bwd_payload_bytes: int = 0
    fragment_count: int = 0

    tcp_state: str = TCP_NONE
    tcp_flag_counts: dict[str, int] = field(default_factory=dict)
    history: str = ""
    client_isn: Optional[int] = None
    syn_seen: bool = False
    synack_seen: bool = False
    handshake_completed: bool = False
    fwd_fin: bool = False
    bwd_fin: bool = False
    fwd_rst: bool = False
    bwd_rst: bool = False
    packets_after_rst: int = 0

    status: str = STATUS_ACTIVE
    termination_reason: Optional[str] = None

    packets: list[Any] = field(default_factory=list)

    def add_packet(
        self,
        packet,
        is_forward: bool,
        size: int,
        store_packet: bool = False,
    ) -> None:
        timestamp = packet.timestamp
        self.first_seen = min(self.first_seen, timestamp)
        self.last_seen = max(self.last_seen, timestamp)
        payload = getattr(packet, "payload", b"") or b""

        self.packet_count += 1
        self.byte_count += size
        self.payload_byte_count += len(payload)
        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += size
            self.fwd_payload_bytes += len(payload)
        else:
            self.bwd_packets += 1
            self.bwd_bytes += size
            self.bwd_payload_bytes += len(payload)

        self.fragment_count += getattr(packet, "reassembled_fragments", 0) or 0
        if store_packet:
            self.packets.append(packet)

        if self.protocol == "TCP" and getattr(packet, "tcp_flags", None) is not None:
            self._update_tcp(packet, is_forward)

    def _mark_history(self, letter: str, is_forward: bool) -> None:
        """Zeek-style history: uppercase = client, lowercase = server."""
        event = letter if is_forward else letter.lower()
        if event not in self.history:
            self.history += event

    def _update_tcp(self, packet, is_forward: bool) -> None:
        flags = packet.tcp_flags
        for bit, name in TCP_FLAG_NAMES:
            if flags & bit:
                self.tcp_flag_counts[name] = self.tcp_flag_counts.get(name, 0) + 1
        if flags == 0:
            self.tcp_flag_counts["NULL"] = self.tcp_flag_counts.get("NULL", 0) + 1

        syn = bool(flags & TCP_SYN)
        ack = bool(flags & TCP_ACK)
        fin = bool(flags & TCP_FIN)
        rst = bool(flags & TCP_RST)
        has_payload = bool(getattr(packet, "payload", b""))

        if syn and not ack:
            self._mark_history("S", is_forward)
        elif syn and ack:
            self._mark_history("H", is_forward)
        elif ack and not (fin or rst or has_payload):
            self._mark_history("A", is_forward)
        if has_payload:
            self._mark_history("D", is_forward)
        if fin:
            self._mark_history("F", is_forward)
        if rst:
            self._mark_history("R", is_forward)

        if rst:
            if is_forward:
                self.fwd_rst = True
            else:
                self.bwd_rst = True
            self.tcp_state = TCP_CLOSED
            return
        if self.tcp_state == TCP_CLOSED:
            # Traffic after a RST: late ACKs, or a forged RST used to blind the IDS.
            self.packets_after_rst += 1
            return

        if syn and not ack:
            if is_forward:
                self.syn_seen = True
                if self.client_isn is None:
                    self.client_isn = getattr(packet, "tcp_seq", None)
            if self.tcp_state == TCP_NONE:
                self.tcp_state = TCP_SYN_SENT
        elif syn and ack:
            if not is_forward:
                self.synack_seen = True
            if self.tcp_state in {TCP_NONE, TCP_SYN_SENT}:
                self.tcp_state = TCP_SYN_RECEIVED
        elif ack and is_forward and self.tcp_state == TCP_SYN_RECEIVED:
            self.tcp_state = TCP_ESTABLISHED
            self.handshake_completed = True
        elif self.tcp_state == TCP_NONE:
            # First packet is neither SYN nor SYN-ACK: handshake was missed.
            self.tcp_state = TCP_MIDSTREAM

        if fin:
            if is_forward:
                self.fwd_fin = True
            else:
                self.bwd_fin = True
            if self.fwd_fin and self.bwd_fin:
                self.tcp_state = TCP_CLOSING
            else:
                self.tcp_state = TCP_FIN_WAIT

    def continue_from(self, previous: "Flow") -> None:
        """Carry TCP context into a flow split by the active timeout."""
        self.is_continuation = True
        for name in (
            "tcp_state",
            "client_isn",
            "syn_seen",
            "synack_seen",
            "handshake_completed",
            "fwd_fin",
            "bwd_fin",
        ):
            setattr(self, name, getattr(previous, name))

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def conn_state(self) -> str:
        """Zeek-like connection summary (S0, REJ, SF, RSTO, ...)."""
        if self.protocol != "TCP":
            return "SF" if self.fwd_packets and self.bwd_packets else "S0"

        if self.syn_seen and not self.synack_seen:
            if self.bwd_rst:
                return "REJ"
            if self.fwd_rst:
                return "RSTOS0"
            if self.fwd_fin:
                return "SH"
            return "S0"
        if self.synack_seen and not self.syn_seen:
            if self.bwd_rst:
                return "RSTRH"
            if self.bwd_fin:
                return "SHR"
            return "OTH"
        if self.syn_seen and self.synack_seen:
            if self.fwd_rst:
                return "RSTO"
            if self.bwd_rst:
                return "RSTR"
            if self.fwd_fin and self.bwd_fin:
                return "SF"
            if self.fwd_fin:
                return "S2"
            if self.bwd_fin:
                return "S3"
            return "S1"
        return "OTH"

    def summary(self) -> str:
        text = (
            f"{self.protocol} {_format_endpoint(self.client, self.protocol)} -> "
            f"{_format_endpoint(self.server, self.protocol)} "
            f"packets={self.packet_count} (fwd={self.fwd_packets} bwd={self.bwd_packets}) "
            f"bytes={self.byte_count} (fwd={self.fwd_bytes} bwd={self.bwd_bytes}) "
            f"duration={self.duration:.6f}s conn_state={self.conn_state}"
        )
        if self.protocol == "TCP":
            flags = ",".join(
                f"{name}:{count}" for name, count in self.tcp_flag_counts.items()
            )
            text += (
                f" tcp_state={self.tcp_state} history={self.history or '-'}"
                f" flags={flags or '-'}"
            )
        if self.packets_after_rst:
            text += f" packets_after_rst={self.packets_after_rst}"
        if self.fragment_count:
            text += f" fragments={self.fragment_count}"
        if self.is_continuation:
            text += " continuation=yes"
        return text + f" end={self.termination_reason or '-'}"
