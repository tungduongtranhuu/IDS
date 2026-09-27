#!/usr/bin/env python3

"""Phase 3 flow manager and PCAP flow-analysis CLI."""

import argparse
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


PHASE_TWO_DIR = Path(__file__).resolve().parents[1] / "phase 2"
sys.path.insert(0, str(PHASE_TWO_DIR))

from packet_decoder import decode_pcap


LOGGER = logging.getLogger(__name__)
OUTPUT_MODES = ("quiet", "normal", "verbose", "debug")
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10

DirectionalKey = tuple[Any, Any, Any, Any, Any]
Endpoint = tuple[Any, Any]
CanonicalKey = tuple[Endpoint, Endpoint, Any]


def packet_flow_key(packet) -> DirectionalKey:
    """Return the directional 5-tuple for a decoded packet."""
    return (
        packet.src_ip,
        packet.src_port,
        packet.dst_ip,
        packet.dst_port,
        packet.ip_protocol,
    )


def canonical_flow_key(flow_key: DirectionalKey) -> CanonicalKey:
    """Normalize both directions of one connection to one flow key."""
    source = (flow_key[0], flow_key[1])
    destination = (flow_key[2], flow_key[3])
    endpoints = sorted((source, destination), key=repr)
    return endpoints[0], endpoints[1], flow_key[4]


@dataclass
class Flow:
    """State and statistics for one bidirectional network flow."""

    key: CanonicalKey
    first_seen: float
    last_seen: float
    protocol: Any
    packets: list[Any] = field(default_factory=list)
    packet_count: int = 0
    byte_count: int = 0
    direction_packet_counts: dict[DirectionalKey, int] = field(default_factory=dict)
    direction_byte_counts: dict[DirectionalKey, int] = field(default_factory=dict)
    tcp_state: str = "NONE"

    def add_packet(self, packet, directional_key: DirectionalKey) -> None:
        timestamp = packet.timestamp
        self.first_seen = min(self.first_seen, timestamp)
        self.last_seen = max(self.last_seen, timestamp)
        packet_size = packet.capture_length or len(packet.payload)
        self.packets.append(packet)
        self.packet_count += 1
        self.byte_count += packet_size
        self.direction_packet_counts[directional_key] = (
            self.direction_packet_counts.get(directional_key, 0) + 1
        )
        self.direction_byte_counts[directional_key] = (
            self.direction_byte_counts.get(directional_key, 0) + packet_size
        )
        self._update_tcp_state(packet)

    def _update_tcp_state(self, packet) -> None:
        if self.protocol != "TCP" or packet.tcp_flags is None:
            return
        flags = packet.tcp_flags
        if flags & TCP_RST:
            self.tcp_state = "CLOSED"
        elif flags & TCP_FIN:
            self.tcp_state = "FIN_WAIT"
        elif flags & TCP_SYN and flags & TCP_ACK:
            self.tcp_state = "SYN_RECEIVED"
        elif flags & TCP_SYN:
            self.tcp_state = "SYN_SENT"
        elif flags & TCP_ACK and self.tcp_state in {"SYN_SENT", "SYN_RECEIVED"}:
            self.tcp_state = "ESTABLISHED"

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def summary(self) -> str:
        first_endpoint, second_endpoint, protocol = self.key
        return (
            f"{protocol} {first_endpoint[0]}:{first_endpoint[1]} <-> "
            f"{second_endpoint[0]}:{second_endpoint[1]} "
            f"packets={self.packet_count} bytes={self.byte_count} "
            f"duration={self.duration:.6f}s state={self.tcp_state}"
        )


class FlowManager:
    """Group decoded packets into bidirectional flows and track their state."""

    def __init__(self, flow_timeout: float = 60.0):
        if flow_timeout <= 0:
            raise ValueError("flow_timeout must be greater than zero")
        self.flow_timeout = flow_timeout
        self.flows: dict[CanonicalKey, Flow] = {}
        self.expired_flows: list[Flow] = []

    def add_packet(self, packet) -> Flow:
        directional_key = packet_flow_key(packet)
        flow_key = canonical_flow_key(directional_key)
        flow = self.flows.get(flow_key)
        if flow is None:
            flow = Flow(
                key=flow_key,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
                protocol=directional_key[4],
            )
            self.flows[flow_key] = flow
        flow.add_packet(packet, directional_key)
        self.expire(timestamp=packet.timestamp)
        return flow

    def expire(self, timestamp: float) -> list[Flow]:
        expired_keys = [
            key
            for key, flow in self.flows.items()
            if timestamp - flow.last_seen >= self.flow_timeout
        ]
        for key in expired_keys:
            self.expired_flows.append(self.flows.pop(key))
        return [flow for flow in self.expired_flows if flow.last_seen <= timestamp]

    def close_all(self) -> list[Flow]:
        closed = list(self.flows.values())
        self.expired_flows.extend(closed)
        self.flows.clear()
        return closed

    def statistics(self) -> dict[str, int]:
        flows = list(self.flows.values()) + self.expired_flows
        return {
            "flows": len(flows),
            "active_flows": len(self.flows),
            "expired_flows": len(self.expired_flows),
            "packets": sum(flow.packet_count for flow in flows),
            "bytes": sum(flow.byte_count for flow in flows),
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
    flow_timeout: float = 60.0,
):
    """Decode a PCAP, build flows, and write the flow report to a text file."""
    root_logger, previous_level, handler = _configure_result_logging(
        result_file,
        output_mode,
    )
    try:
        LOGGER.info("CUSTOM IDS - PHASE 3 FLOW MANAGER")
        LOGGER.info("PCAP file: %s", filename)
        LOGGER.info("Output mode: %s", output_mode)
        LOGGER.info("Flow timeout: %.3f seconds", flow_timeout)
        decoder = decode_pcap(
            filename=filename,
            packet_limit=packet_limit,
            output_mode="quiet",
        )
        manager = FlowManager(flow_timeout=flow_timeout)
        for packet in decoder.packets:
            manager.add_packet(packet)
        manager.close_all()

        stats = manager.statistics()
        LOGGER.info(
            "Flow statistics: flows=%d packets=%d bytes=%d active=%d expired=%d",
            stats["flows"],
            stats["packets"],
            stats["bytes"],
            stats["active_flows"],
            stats["expired_flows"],
        )
        if output_mode in {"verbose", "debug"}:
            for index, flow in enumerate(manager.expired_flows, start=1):
                LOGGER.info("Flow #%d: %s", index, flow.summary())
                if output_mode == "debug":
                    for packet_index, packet in enumerate(flow.packets, start=1):
                        LOGGER.debug(
                            "  packet #%d: %s timestamp=%s payload_length=%d",
                            packet_index,
                            packet.summary(),
                            packet.timestamp,
                            packet.payload_length(),
                        )
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
    parser.add_argument("--timeout", type=float, default=60.0)
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
    )


if __name__ == "__main__":
    main()
