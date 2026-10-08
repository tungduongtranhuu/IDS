"""Phase 5 behavioral state: sliding windows, scan episodes, DNS query features.

Everything runs on packet timestamps (never the wall clock), like Phase 3,
so a PCAP replay gives the same alerts as the live capture did.
"""

import math
import struct
from collections import Counter, deque
from collections.abc import Hashable
from dataclasses import dataclass, field
from typing import Any, Optional

import dpkt


TCP_SYN = 0x02
TCP_ACK = 0x10

TECHNIQUE_HALF_OPEN = "half_open"
TECHNIQUE_CONNECT = "connect"
TECHNIQUE_SERVICE = "service"
TECHNIQUE_OTHER = "other"

DEFAULT_SCAN_IDLE_TIMEOUT = 10.0
DEFAULT_SCAN_MAX_DURATION = 60.0
DEFAULT_MAX_TRACKED_KEYS = 100_000


class SlidingWindow:
    """Per-key sliding window: did `count` events happen within `seconds`?

    Only the last `count` events of a key are kept, so memory is bounded by
    count x keys. An optional item (sample query, port...) is stored with each
    event and returned as evidence.
    """

    def __init__(self, count: int, seconds: float, max_keys: int = DEFAULT_MAX_TRACKED_KEYS):
        self.count = count
        self.seconds = seconds
        self.max_keys = max_keys
        self.events: dict[Hashable, deque] = {}

    def add(self, key: Hashable, timestamp: float, item: Any = None) -> Optional[list[tuple[float, Any]]]:
        """Record one event. Return the events in the window when the threshold is reached."""
        window = self.events.get(key)
        if window is None:
            if len(self.events) >= self.max_keys:
                self.expire(timestamp)
                if len(self.events) >= self.max_keys:
                    # Still full: forget the oldest key (dicts keep insertion order).
                    del self.events[next(iter(self.events))]
            window = self.events[key] = deque(maxlen=self.count)
        window.append((timestamp, item))
        if len(window) == self.count and timestamp - window[0][0] <= self.seconds:
            return list(window)
        return None

    def contains(self, key: Hashable, item: Any) -> bool:
        return any(stored == item for _timestamp, stored in self.events.get(key, ()))

    def reset(self, key: Hashable) -> None:
        self.events.pop(key, None)

    def expire(self, timestamp: float) -> int:
        """Forget keys whose newest event left the window."""
        stale = [key for key, window in self.events.items() if timestamp - window[-1][0] > self.seconds]
        for key in stale:
            del self.events[key]
        return len(stale)


@dataclass
class PortProbe:
    first_seen: float
    syn: bool = False
    completed: bool = False
    client_payload: bool = False


@dataclass
class ScanEpisode:
    """TCP activity of one source towards one target, until it goes quiet.

    A port is "probed" when the source opens a new TCP flow to it. For each
    port we remember whether the probe was a SYN, whether the source completed
    the handshake, and whether it then sent application data (a probe).
    """

    src_ip: str
    dst_ip: str
    start: float
    last_activity: float
    ports: dict[int, PortProbe] = field(default_factory=dict)
    connections: int = 0

    @property
    def duration(self) -> float:
        return self.last_activity - self.start

    def probe(self, port: int, timestamp: float, syn: bool) -> None:
        self.connections += 1
        probe = self.ports.get(port)
        if probe is None:
            probe = self.ports[port] = PortProbe(first_seen=timestamp)
        probe.syn = probe.syn or syn

    def count(self, attribute: str) -> int:
        return sum(1 for probe in self.ports.values() if getattr(probe, attribute))

    @property
    def technique(self) -> str:
        """One label per episode, most specific first, so scan rules never overlap.

        service   : the source completed handshakes AND sent data (nmap -sV probes)
        connect   : handshakes completed, no data (nmap -sT, connect() scans)
        half_open : SYN probes, handshake never completed (nmap -sS)
        other     : no SYN at all (FIN / NULL / XMAS probes, mid-stream traffic)
        """
        if self.count("client_payload"):
            return TECHNIQUE_SERVICE
        if self.count("completed"):
            return TECHNIQUE_CONNECT
        if self.count("syn"):
            return TECHNIQUE_HALF_OPEN
        return TECHNIQUE_OTHER

    def peak_ports(self, seconds: float) -> int:
        """Most distinct ports first probed within any window of `seconds`."""
        times = sorted(probe.first_seen for probe in self.ports.values())
        best = 0
        start = 0
        for end, timestamp in enumerate(times):
            while timestamp - times[start] > seconds:
                start += 1
            best = max(best, end - start + 1)
        return best

    def evidence(self, seconds: float) -> dict[str, Any]:
        ports = sorted(self.ports)
        return {
            "technique": self.technique,
            "ports_probed": len(ports),
            "peak_ports_in_window": self.peak_ports(seconds),
            "window_seconds": seconds,
            "connections": self.connections,
            "handshakes_completed": self.count("completed"),
            "service_ports": sorted(port for port, probe in self.ports.items() if probe.client_payload),
            "sample_ports": ports[:25],
            "first_seen": self.start,
            "last_seen": self.last_activity,
            "duration_seconds": round(self.duration, 6),
        }


class ScanTracker:
    """Group TCP probes into episodes per (source, target) and close them when idle.

    The technique of an episode is only known once it is over: a connect scan
    reaches the few open ports at random moments, and nmap -sV sends its
    probes seconds after the port scan. So episodes are classified when the
    source has been quiet for `idle_timeout` seconds (or after `max_duration`
    for very long scans, or at the end of the capture).
    """

    def __init__(
        self,
        idle_timeout: float = DEFAULT_SCAN_IDLE_TIMEOUT,
        max_duration: float = DEFAULT_SCAN_MAX_DURATION,
        max_episodes: int = DEFAULT_MAX_TRACKED_KEYS,
    ):
        if idle_timeout <= 0 or max_duration <= 0:
            raise ValueError("scan timeouts must be greater than zero")
        self.idle_timeout = idle_timeout
        self.max_duration = max_duration
        self.max_episodes = max_episodes
        self.episodes: dict[tuple[str, str], ScanEpisode] = {}
        self.episodes_closed = 0

    def observe(self, flow, packet, is_forward: bool) -> None:
        """FlowManager on_packet view of a TCP packet (after the flow was updated)."""
        if not is_forward or flow.protocol != "TCP":
            return
        key = (flow.client[0], flow.server[0])
        timestamp = packet.timestamp
        port = flow.server[1]
        flags = getattr(packet, "tcp_flags", 0) or 0
        episode = self.episodes.get(key)

        if flow.fwd_packets == 1:
            # First packet the source sends in this flow: a new probe.
            if episode is None:
                if len(self.episodes) >= self.max_episodes:
                    self._evict_oldest()
                episode = self.episodes[key] = ScanEpisode(key[0], key[1], timestamp, timestamp)
            episode.probe(port, timestamp, bool(flags & TCP_SYN) and not flags & TCP_ACK)
        if episode is None:
            return
        episode.last_activity = max(episode.last_activity, timestamp)
        probe = episode.ports.get(port)
        if probe is None:
            return
        if flow.handshake_completed:
            probe.completed = True
            if getattr(packet, "payload", b""):
                probe.client_payload = True

    def _evict_oldest(self) -> None:
        oldest = min(self.episodes, key=lambda key: self.episodes[key].last_activity)
        del self.episodes[oldest]

    def expire(self, timestamp: float) -> list[ScanEpisode]:
        """Close episodes that went quiet or lasted too long."""
        closed = []
        for key, episode in list(self.episodes.items()):
            idle = timestamp - episode.last_activity >= self.idle_timeout
            too_long = timestamp - episode.start >= self.max_duration
            if idle or too_long:
                del self.episodes[key]
                closed.append(episode)
        self.episodes_closed += len(closed)
        return closed

    def flush(self) -> list[ScanEpisode]:
        closed = list(self.episodes.values())
        self.episodes.clear()
        self.episodes_closed += len(closed)
        return closed


def shannon_entropy(text: str) -> float:
    """Bits per character of `text` (0 for empty or one repeated character)."""
    if not text:
        return 0.0
    length = len(text)
    return -sum(count / length * math.log2(count / length) for count in Counter(text).values())


@dataclass(frozen=True)
class DnsQueryFeatures:
    qname: str
    base_domain: str
    subdomain: str
    subdomain_length: int
    longest_label: int
    entropy: float


def dns_query_features(payload: bytes) -> Optional[DnsQueryFeatures]:
    """Features of the first question of a DNS query, or None if it is not one.

    The base domain is approximated by the last two labels (no public suffix
    list): "a1b2...f9.example.com" -> base "example.com", subdomain "a1b2...f9".
    Entropy is measured on the subdomain without dots.
    """
    try:
        message = dpkt.dns.DNS(payload)
    except (dpkt.dpkt.Error, struct.error, IndexError, ValueError, UnicodeDecodeError):
        return None
    if message.qr != dpkt.dns.DNS_Q or not message.qd:
        return None
    qname = (message.qd[0].name or "").lower().rstrip(".")
    labels = [label for label in qname.split(".") if label]
    if not labels:
        return None
    base = ".".join(labels[-2:])
    sub_labels = labels[:-2]
    subdomain = ".".join(sub_labels)
    return DnsQueryFeatures(
        qname=qname,
        base_domain=base,
        subdomain=subdomain,
        subdomain_length=len(subdomain),
        longest_label=max(len(label) for label in labels),
        entropy=round(shannon_entropy(subdomain.replace(".", "")), 3),
    )
