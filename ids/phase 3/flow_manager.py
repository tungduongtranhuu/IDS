#!/usr/bin/env python3

"""Phase 3 flow manager.

Pipeline (streaming, one packet at a time):

    PCAP file / live source -> [Phase 4 IpDefragmenter] -> PacketDecoder
        -> FlowManager.add_packet() -> on_packet hook (Phase 4 reassembly)
        -> finished Flow objects -> on_flow_end hook

IP fragments are reassembled by Phase 4 before packets reach this module.
Non-first fragments that still arrive here (no defragmenter in front) carry
no ports, so they are counted as ignored_fragments and not put in any flow.

The building blocks live in their own modules and are re-exported here, so
`from flow_manager import Flow, FlowTimeouts, TCP_SYN, ...` keeps working:

    flow_constants  TCP flags/states, flow status and end reasons
    flow_keys       flow keys and client/server guess
    flow_utils      packet size and fragment helpers
    flow_timeouts   FlowTimeouts and default timeouts
    flow            Flow (one bidirectional flow)
    flow_cli        PCAP report CLI (also run by `python flow_manager.py`)
"""

from collections.abc import Callable
from typing import Any, Optional

from flow import Flow
from flow_constants import (
    END_ACTIVE_TIMEOUT,
    END_OF_CAPTURE,
    END_TCP_FIN,
    END_TCP_PORT_REUSE,
    END_TCP_RST,
    END_TIMEOUT,
    ICMP_REPLY_TYPES,
    STATUS_ACTIVE,
    STATUS_CLOSED,
    STATUS_EXPIRED,
    TCP_ACK,
    TCP_CLOSED,
    TCP_CLOSING,
    TCP_CWR,
    TCP_ECE,
    TCP_ESTABLISHED,
    TCP_FIN,
    TCP_FIN_WAIT,
    TCP_FLAG_NAMES,
    TCP_MIDSTREAM,
    TCP_NONE,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    TCP_SYN_RECEIVED,
    TCP_SYN_SENT,
    TCP_URG,
)
from flow_keys import (
    CanonicalKey,
    DirectionalKey,
    Endpoint,
    canonical_flow_key,
    guess_client,
    packet_flow_key,
)
from flow_timeouts import DEFAULT_ACTIVE_TIMEOUT, DEFAULT_SWEEP_INTERVAL, FlowTimeouts
from flow_utils import is_non_first_fragment, packet_size


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


if __name__ == "__main__":
    # Kept so `python "ids/phase 3/flow_manager.py" <pcap> ...` still works.
    from flow_cli import main

    main()
