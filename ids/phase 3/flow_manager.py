#!/usr/bin/env python3

"""Phase 3 flow manager and PCAP flow-analysis CLI.

Pipeline (streaming, one packet at a time):

    PCAP file / live source -> [Phase 4 IpDefragmenter] -> PacketDecoder
        -> FlowManager.add_packet() -> on_packet hook (Phase 4 reassembly)
        -> finished Flow objects -> on_flow_end hook

IP fragments are reassembled by Phase 4 before packets reach this module.
Non-first fragments that still arrive here (no defragmenter in front) carry
no ports, so they are counted as ignored_fragments and not put in any flow.
"""

import argparse
import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Optional

import dpkt


PHASE_TWO_DIR = Path(__file__).resolve().parents[1] / "phase 2"
sys.path.insert(0, str(PHASE_TWO_DIR))

from packet_decoder import PacketDecoder, iter_decoded_packets


LOGGER = logging.getLogger(__name__)
OUTPUT_MODES = ("quiet", "normal", "verbose", "debug")

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80
TCP_FLAG_NAMES = (
    (TCP_SYN, "SYN"),
    (TCP_FIN, "FIN"),
    (TCP_RST, "RST"),
    (TCP_PSH, "PSH"),
    (TCP_ACK, "ACK"),
    (TCP_URG, "URG"),
    (TCP_ECE, "ECE"),
    (TCP_CWR, "CWR"),
)

# Lifecycle states of a TCP flow (both directions combined).
TCP_NONE = "NONE"
TCP_SYN_SENT = "SYN_SENT"
TCP_SYN_RECEIVED = "SYN_RECEIVED"
TCP_ESTABLISHED = "ESTABLISHED"
TCP_MIDSTREAM = "MIDSTREAM"
TCP_FIN_WAIT = "FIN_WAIT"
TCP_CLOSING = "CLOSING"
TCP_CLOSED = "CLOSED"

# ICMP reply types: the sender of a reply is the server side.
ICMP_REPLY_TYPES = {0, 14, 16, 18}

# Flow status and termination reasons.
STATUS_ACTIVE = "ACTIVE"
STATUS_EXPIRED = "EXPIRED"
STATUS_CLOSED = "CLOSED"
END_TIMEOUT = "TIMEOUT"
END_ACTIVE_TIMEOUT = "ACTIVE_TIMEOUT"
END_TCP_RST = "TCP_RST"
END_TCP_FIN = "TCP_FIN"
END_TCP_PORT_REUSE = "TCP_PORT_REUSE"
END_OF_CAPTURE = "END_OF_CAPTURE"

DEFAULT_ACTIVE_TIMEOUT = 120.0
DEFAULT_SWEEP_INTERVAL = 1.0

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


def _format_endpoint(endpoint: Endpoint, protocol: Any) -> str:
    ip, port = endpoint
    if port is None:
        return str(ip)
    if protocol == "ICMP":
        return f"{ip}[id={port}]"
    return f"{ip}:{port}"


@dataclass(frozen=True)
class FlowTimeouts:
    """Idle timeouts in seconds, chosen per protocol and TCP state."""

    tcp_new: float = 30.0
    tcp_established: float = 300.0
    tcp_closing: float = 5.0
    tcp_closed: float = 2.0
    udp: float = 60.0
    icmp: float = 30.0
    other: float = 60.0

    @classmethod
    def from_single_timeout(cls, seconds: float) -> "FlowTimeouts":
        """Use one idle timeout everywhere, keeping closing TCP flows short."""
        return cls(
            tcp_new=seconds,
            tcp_established=seconds,
            tcp_closing=min(seconds, cls.tcp_closing),
            tcp_closed=min(seconds, cls.tcp_closed),
            udp=seconds,
            icmp=seconds,
            other=seconds,
        )

    def validate(self) -> None:
        for item in fields(self):
            if getattr(self, item.name) <= 0:
                raise ValueError(f"timeout {item.name} must be greater than zero")

    def idle_timeout(self, flow: "Flow") -> float:
        if flow.protocol == "TCP":
            if flow.tcp_state == TCP_CLOSED:
                return self.tcp_closed
            if flow.tcp_state == TCP_CLOSING:
                return self.tcp_closing
            if flow.tcp_state in {TCP_ESTABLISHED, TCP_MIDSTREAM, TCP_FIN_WAIT}:
                return self.tcp_established
            return self.tcp_new
        if flow.protocol == "UDP":
            return self.udp
        if flow.protocol == "ICMP":
            return self.icmp
        return self.other


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


FlowEndCallback = Callable[[Flow], None]
# on_packet(flow, packet, is_forward): is_forward is True for client -> server.
PacketCallback = Callable[[Flow, Any, bool], None]


class FlowManager:
    """Group decoded packets into bidirectional flows and track their state.

    Packets are processed one at a time with add_packet(). After each packet is
    added to its flow, on_packet is called (the hook for Phase 4 reassembly).
    Finished flows are handed to on_flow_end and then forgotten, unless
    keep_finished_flows=True.
    """

    def __init__(
        self,
        flow_timeout: Optional[float] = None,
        *,
        timeouts: Optional[FlowTimeouts] = None,
        active_timeout: float = DEFAULT_ACTIVE_TIMEOUT,
        sweep_interval: float = DEFAULT_SWEEP_INTERVAL,
        store_packets: bool = False,
        keep_finished_flows: bool = False,
        on_packet: Optional[PacketCallback] = None,
        on_flow_end: Optional[FlowEndCallback] = None,
    ):
        if flow_timeout is not None:
            if flow_timeout <= 0:
                raise ValueError("flow_timeout must be greater than zero")
            if timeouts is not None:
                raise ValueError("pass either flow_timeout or timeouts, not both")
            timeouts = FlowTimeouts.from_single_timeout(flow_timeout)
        self.timeouts = timeouts or FlowTimeouts()
        self.timeouts.validate()
        for name, value in (
            ("active_timeout", active_timeout),
            ("sweep_interval", sweep_interval),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")

        self.active_timeout = active_timeout
        self.sweep_interval = sweep_interval
        self.store_packets = store_packets
        self.keep_finished_flows = keep_finished_flows
        self.on_packet = on_packet
        self.on_flow_end = on_flow_end

        self.flows: dict[CanonicalKey, Flow] = {}
        self.expired_flows: list[Flow] = []
        self.clock: Optional[float] = None
        self._last_sweep: Optional[float] = None

        self.flows_created = 0
        self.flows_finished = 0
        self.packet_total = 0
        self.byte_total = 0
        self.ignored_fragments = 0
        self.sweeps = 0
        self.termination_counts: dict[str, int] = {}

    def add_packet(self, packet) -> Optional[Flow]:
        """Process one decoded packet and return the flow it was added to.

        Returns None for a non-first IP fragment (see module docstring).
        """
        self._advance_clock(packet.timestamp)
        if is_non_first_fragment(packet):
            self.ignored_fragments += 1
            flow = None
        else:
            flow = self._add_regular_packet(packet)
        self._maybe_sweep()
        return flow

    def _advance_clock(self, timestamp: float) -> None:
        if self.clock is None or timestamp > self.clock:
            self.clock = timestamp

    def _add_regular_packet(self, packet) -> Flow:
        directional_key = packet_flow_key(packet)
        flow_key = canonical_flow_key(directional_key)
        flow = self.flows.get(flow_key)
        previous = None

        if flow is not None:
            ending = self._ending_before_packet(flow, packet)
            if ending is not None:
                status, reason = ending
                self._finish(flow, status, reason)
                if reason == END_ACTIVE_TIMEOUT:
                    previous = flow
                flow = None

        if flow is None:
            flow = self._create_flow(packet, directional_key, flow_key, previous)

        is_forward = (directional_key[0], directional_key[1]) == flow.client
        self._assign(flow, packet, is_forward)
        return flow

    def _ending_before_packet(self, flow: Flow, packet) -> Optional[tuple[str, str]]:
        """Decide whether flow must end before this packet is added to it."""
        timestamp = packet.timestamp
        if timestamp - flow.last_seen >= self.timeouts.idle_timeout(flow):
            return self._idle_ending(flow)
        if timestamp - flow.first_seen >= self.active_timeout:
            return STATUS_EXPIRED, END_ACTIVE_TIMEOUT
        if self._is_new_tcp_connection(flow, packet):
            if flow.tcp_state in {TCP_CLOSED, TCP_CLOSING}:
                return self._idle_ending(flow)
            return STATUS_CLOSED, END_TCP_PORT_REUSE
        return None

    @staticmethod
    def _idle_ending(flow: Flow) -> tuple[str, str]:
        if flow.protocol == "TCP":
            if flow.tcp_state == TCP_CLOSED:
                return STATUS_CLOSED, END_TCP_RST
            if flow.tcp_state == TCP_CLOSING:
                return STATUS_CLOSED, END_TCP_FIN
        return STATUS_EXPIRED, END_TIMEOUT

    @staticmethod
    def _is_new_tcp_connection(flow: Flow, packet) -> bool:
        """A fresh SYN on a closed/closing/established flow starts a new connection."""
        if flow.protocol != "TCP":
            return False
        flags = getattr(packet, "tcp_flags", None)
        if flags is None or not flags & TCP_SYN or flags & TCP_ACK:
            return False
        if flow.tcp_state in {TCP_FIN_WAIT, TCP_CLOSING, TCP_CLOSED}:
            return True
        if flow.tcp_state in {TCP_ESTABLISHED, TCP_MIDSTREAM}:
            sequence = getattr(packet, "tcp_seq", None)
            return flow.client_isn is None or sequence != flow.client_isn
        return False

    def _create_flow(
        self,
        packet,
        directional_key: DirectionalKey,
        flow_key: CanonicalKey,
        previous: Optional[Flow],
    ) -> Flow:
        if previous is not None:
            client, server = previous.client, previous.server
        else:
            client, server = guess_client(packet, directional_key)
        flow = Flow(
            key=flow_key,
            protocol=directional_key[4],
            client=client,
            server=server,
            first_seen=packet.timestamp,
            last_seen=packet.timestamp,
        )
        if previous is not None:
            flow.continue_from(previous)
        self.flows[flow_key] = flow
        self.flows_created += 1
        return flow

    def _assign(self, flow: Flow, packet, is_forward: bool) -> None:
        size = packet_size(packet)
        flow.add_packet(packet, is_forward, size, store_packet=self.store_packets)
        self.packet_total += 1
        self.byte_total += size
        if self.on_packet is not None:
            self.on_packet(flow, packet, is_forward)

    def _maybe_sweep(self) -> None:
        if self._last_sweep is None:
            self._last_sweep = self.clock
        elif self.clock - self._last_sweep >= self.sweep_interval:
            self.expire(self.clock)

    def expire(self, timestamp: float) -> list[Flow]:
        """Finish every flow that has been idle too long at `timestamp`.

        Called automatically every sweep_interval seconds of packet time.
        A live capture loop should also call it on a timer.
        """
        self._advance_clock(timestamp)
        self._last_sweep = timestamp
        self.sweeps += 1

        expired = []
        for flow in list(self.flows.values()):
            if timestamp - flow.last_seen >= self.timeouts.idle_timeout(flow):
                status, reason = self._idle_ending(flow)
                self._finish(flow, status, reason)
                expired.append(flow)
        return expired

    def _finish(self, flow: Flow, status: str, reason: str) -> None:
        if self.flows.get(flow.key) is flow:
            del self.flows[flow.key]
        flow.status = status
        flow.termination_reason = reason
        self.flows_finished += 1
        self.termination_counts[reason] = self.termination_counts.get(reason, 0) + 1
        if self.keep_finished_flows:
            self.expired_flows.append(flow)
        if self.on_flow_end is not None:
            self.on_flow_end(flow)

    def close_all(self) -> list[Flow]:
        """Finish all remaining flows at the end of a capture."""
        closed = list(self.flows.values())
        for flow in closed:
            self._finish(flow, STATUS_CLOSED, END_OF_CAPTURE)
        return closed

    def statistics(self) -> dict[str, int]:
        return {
            "flows": self.flows_created,
            "active_flows": len(self.flows),
            "finished_flows": self.flows_finished,
            "expired_flows": self.flows_finished,
            "packets": self.packet_total,
            "bytes": self.byte_total,
            "ignored_fragments": self.ignored_fragments,
            "sweeps": self.sweeps,
        }


def _configure_result_logging(result_file, output_mode):
    levels = {
        "quiet": logging.ERROR,
        "normal": logging.INFO,
        "verbose": logging.INFO,
        "debug": logging.DEBUG,
    }
    result_path = Path(result_file)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(result_path, mode="w", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root_logger = logging.getLogger()
    previous_level = root_logger.level
    root_logger.setLevel(levels[output_mode])
    root_logger.addHandler(handler)
    return root_logger, previous_level, handler


def analyze_pcap_to_file(
    filename,
    result_file,
    packet_limit: Optional[int] = None,
    output_mode: str = "normal",
    flow_timeout: Optional[float] = None,
    active_timeout: float = DEFAULT_ACTIVE_TIMEOUT,
):
    """Stream a PCAP through the decoder and flow manager into a text report."""
    root_logger, previous_level, handler = _configure_result_logging(
        result_file,
        output_mode,
    )
    try:
        LOGGER.info("CUSTOM IDS - PHASE 3 FLOW MANAGER")
        LOGGER.info("PCAP file: %s", filename)
        LOGGER.info("Output mode: %s", output_mode)

        flow_number = 0

        def report_flow(flow: Flow) -> None:
            nonlocal flow_number
            flow_number += 1
            if output_mode not in {"verbose", "debug"}:
                return
            LOGGER.info("Flow #%d: %s", flow_number, flow.summary())
            if output_mode == "debug":
                for packet_index, packet in enumerate(flow.packets, start=1):
                    LOGGER.debug(
                        "  packet #%d: %s timestamp=%s payload_length=%d",
                        packet_index,
                        packet.summary(),
                        packet.timestamp,
                        packet.payload_length(),
                    )

        manager = FlowManager(
            flow_timeout=flow_timeout,
            active_timeout=active_timeout,
            store_packets=output_mode == "debug",
            on_flow_end=report_flow,
        )
        LOGGER.info("Idle timeouts: %s", manager.timeouts)
        LOGGER.info("Active timeout: %.3f seconds", manager.active_timeout)

        decoder = PacketDecoder(output_mode="quiet", keep_packets=False)
        try:
            for packet in iter_decoded_packets(filename, decoder, packet_limit):
                manager.add_packet(packet)
        except FileNotFoundError:
            LOGGER.error("PCAP file not found: %s", filename)
        except (ValueError, dpkt.dpkt.Error) as error:
            LOGGER.error("Could not decode PCAP: %s", error)
        manager.close_all()
        decoder.print_statistics()

        stats = manager.statistics()
        LOGGER.info(
            "Flow statistics: flows=%d packets=%d bytes=%d active=%d finished=%d "
            "ignored_fragments=%d sweeps=%d",
            stats["flows"],
            stats["packets"],
            stats["bytes"],
            stats["active_flows"],
            stats["finished_flows"],
            stats["ignored_fragments"],
            stats["sweeps"],
        )
        LOGGER.info("Flow end reasons: %s", manager.termination_counts)
        return manager
    finally:
        handler.flush()
        root_logger.removeHandler(handler)
        handler.close()
        root_logger.setLevel(previous_level)


def get_arguments(arguments=None):
    parser = argparse.ArgumentParser(description="Phase 3 flow manager")
    parser.add_argument("pcap", help="PCAP file generated by packet_capture.py")
    parser.add_argument("-n", "--limit", type=int, default=None)
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="One idle timeout for every protocol (default: per-protocol timeouts)",
    )
    parser.add_argument(
        "--active-timeout",
        type=float,
        default=DEFAULT_ACTIVE_TIMEOUT,
        help="Maximum flow duration before it is split",
    )
    parser.add_argument("--mode", choices=OUTPUT_MODES, default="normal")
    parser.add_argument(
        "--result",
        default="flow_manager_result.txt",
        help="Text file for flow output",
    )
    return parser.parse_args(arguments)


def main(arguments=None):
    args = get_arguments(arguments)
    analyze_pcap_to_file(
        filename=args.pcap,
        result_file=args.result,
        packet_limit=args.limit,
        output_mode=args.mode,
        flow_timeout=args.timeout,
        active_timeout=args.active_timeout,
    )


if __name__ == "__main__":
    main()
