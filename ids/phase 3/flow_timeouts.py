"""Idle timeouts per protocol and TCP state, plus manager-wide defaults."""

from dataclasses import dataclass, fields
from typing import TYPE_CHECKING

from flow_constants import (
    TCP_CLOSED,
    TCP_CLOSING,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT,
    TCP_MIDSTREAM,
)

if TYPE_CHECKING:
    from flow import Flow


DEFAULT_ACTIVE_TIMEOUT = 120.0
DEFAULT_SWEEP_INTERVAL = 1.0


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
