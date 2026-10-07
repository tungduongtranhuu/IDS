"""Phase 4 TCP stream reassembly (RFC 9293 sequence numbers).

Plugs into the Phase 3 FlowManager hooks:

    reassembler = TcpReassembler(on_data=...)
    FlowManager(on_packet=reassembler.process, on_flow_end=reassembler.close_flow)

Every TCP connection gets two StreamDirection objects (client -> server and
server -> client). Segments are placed by sequence number, so out-of-order,
retransmitted and overlapping segments still produce the byte stream the
endpoint application reads. Newly contiguous bytes are pushed to on_data.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Optional

from sparse_buffer import OVERLAP_FIRST, OVERLAP_POLICIES, SparseBuffer


TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
SEQ_SPACE = 1 << 32
HALF_SEQ_SPACE = 1 << 31

DEFAULT_MAX_STREAM_BYTES = 1024 * 1024
DEFAULT_MAX_WINDOW_BYTES = 1024 * 1024

# Normal on real networks, reported for context.
TCP_OUT_OF_ORDER = "TCP_OUT_OF_ORDER"
TCP_RETRANSMISSION = "TCP_RETRANSMISSION"
TCP_OVERLAP = "TCP_OVERLAP"
TCP_STREAM_TRUNCATED = "TCP_STREAM_TRUNCATED"
TCP_GAP = "TCP_GAP"
# Rare in benign traffic, typical of evasion attempts.
TCP_OVERLAP_CONFLICT = "TCP_OVERLAP_CONFLICT"
TCP_OLD_DATA = "TCP_OLD_DATA"
TCP_OUT_OF_WINDOW = "TCP_OUT_OF_WINDOW"
TCP_RST_PAYLOAD = "TCP_RST_PAYLOAD"
# IP defrag anomalies of packets that carried this stream (set by ip_defrag).
SUSPICIOUS_FRAGMENT_ANOMALIES = frozenset(
    {"FRAG_OVERLAP_CONFLICT", "FRAG_TINY_FIRST", "FRAG_BAD_LENGTH"}
)
SUSPICIOUS_TCP_ANOMALIES = frozenset(
    {TCP_OVERLAP_CONFLICT, TCP_OLD_DATA, TCP_OUT_OF_WINDOW, TCP_RST_PAYLOAD}
) | SUSPICIOUS_FRAGMENT_ANOMALIES

ACTIVE_TIMEOUT_REASON = "ACTIVE_TIMEOUT"


def seq_offset(seq: int, base: int) -> int:
    """Signed distance seq - base in 32-bit sequence space (handles wraparound)."""
    return ((seq - base + HALF_SEQ_SPACE) % SEQ_SPACE) - HALF_SEQ_SPACE


@dataclass
class StreamDirection:
    """Reassembled byte stream of one direction of a TCP connection.

    Offsets are relative to base_seq: offset 0 is the first data byte.
    `data` holds bytes [0, next_offset) (up to max_stream_bytes);
    `pending` holds out-of-order bytes, its offset 0 = next_offset.
    """

    base_seq: Optional[int] = None
    next_offset: int = 0
    data: bytearray = field(default_factory=bytearray)
    pending: SparseBuffer = field(default_factory=SparseBuffer)
    segments: int = 0
    bytes_seen: int = 0
    out_of_order_segments: int = 0
    retransmitted_bytes: int = 0
    overlap_bytes: int = 0
    conflict_bytes: int = 0
    dropped_bytes: int = 0
    truncated: bool = False
    anomalies: dict[str, int] = field(default_factory=dict)
    unassembled: list[tuple[int, bytes]] = field(default_factory=list)

    @property
    def next_seq(self) -> Optional[int]:
        if self.base_seq is None:
            return None
        return (self.base_seq + self.next_offset) % SEQ_SPACE

    @property
    def pending_bytes(self) -> int:
        return self.pending.covered_bytes

    def mark(self, anomaly: str, count: int = 1) -> None:
        self.anomalies[anomaly] = self.anomalies.get(anomaly, 0) + count

    def add_segment(
        self,
        seq: int,
        payload: bytes,
        policy: str = OVERLAP_FIRST,
        max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
        max_window_bytes: int = DEFAULT_MAX_WINDOW_BYTES,
    ) -> bytes:
        """Place one segment's payload and return the bytes that became contiguous."""
        if not payload:
            return b""
        self.segments += 1
        self.bytes_seen += len(payload)
        if self.base_seq is None:
            # Handshake not seen: the first data segment defines offset 0.
            self.base_seq = seq

        offset = seq_offset(seq, self.base_seq)
        end = offset + len(payload)
        if end <= 0:
            self.mark(TCP_OLD_DATA)
            self.dropped_bytes += len(payload)
            return b""
        if offset < 0:
            self.mark(TCP_OLD_DATA)
            self.dropped_bytes += -offset
            payload = payload[-offset:]
            offset = 0

        if offset < self.next_offset:
            overlap_end = min(end, self.next_offset)
            self._check_retransmission(offset, payload[:overlap_end - offset])
            payload = payload[overlap_end - offset:]
            offset = overlap_end
            if not payload:
                return b""

        relative = offset - self.next_offset
        if relative + len(payload) > max_window_bytes:
            self.mark(TCP_OUT_OF_WINDOW)
            self.dropped_bytes += len(payload)
            return b""
        if relative > 0:
            self.out_of_order_segments += 1
            self.mark(TCP_OUT_OF_ORDER)

        result = self.pending.write(relative, payload, policy)
        if result.overlap_bytes:
            self.overlap_bytes += result.overlap_bytes
            self.mark(TCP_OVERLAP)
        if result.conflict_bytes:
            self.conflict_bytes += result.conflict_bytes
            self.mark(TCP_OVERLAP_CONFLICT)

        ready = self.pending.contiguous_end(0)
        if not ready:
            return b""
        chunk = self.pending.pop_front(ready)
        self.next_offset += len(chunk)
        self._store(chunk, max_stream_bytes)
        return chunk

    def _check_retransmission(self, offset: int, resent: bytes) -> None:
        """Compare re-sent bytes with what was already assembled (cannot be changed)."""
        self.retransmitted_bytes += len(resent)
        self.mark(TCP_RETRANSMISSION)
        kept = self.data[offset:offset + len(resent)]
        differing = sum(1 for old, new in zip(kept, resent) if old != new)
        if differing:
            self.conflict_bytes += differing
            self.mark(TCP_OVERLAP_CONFLICT)

    def _store(self, chunk: bytes, max_stream_bytes: int) -> None:
        room = max_stream_bytes - len(self.data)
        if room > 0:
            self.data.extend(chunk[:room])
        if len(chunk) > max(room, 0) and not self.truncated:
            self.truncated = True
            self.mark(TCP_STREAM_TRUNCATED)

    def finish(self) -> None:
        """At connection end, keep bytes stuck behind a hole as unassembled chunks."""
        if self.pending.is_empty:
            return
        self.mark(TCP_GAP)
        self.unassembled = [
            (self.next_offset + start, chunk) for start, chunk in self.pending.chunks()
        ]
        self.pending = SparseBuffer()

    def summary(self) -> str:
        anomalies = ",".join(f"{name}:{count}" for name, count in self.anomalies.items())
        return (
            f"assembled={self.next_offset} segments={self.segments} "
            f"out_of_order={self.out_of_order_segments} "
            f"retransmitted={self.retransmitted_bytes} overlap={self.overlap_bytes} "
            f"conflict={self.conflict_bytes} dropped={self.dropped_bytes} "
            f"unassembled={sum(len(chunk) for _offset, chunk in self.unassembled)} "
            f"anomalies={anomalies or '-'}"
        )


@dataclass
class TcpStream:
    """Both directions of one TCP connection, tied to its Phase 3 Flow."""

    flow: Any
    client: StreamDirection = field(default_factory=StreamDirection)
    server: StreamDirection = field(default_factory=StreamDirection)
    closed: bool = False
    # Free slot for later stages (HTTP parser state, detection context...).
    context: dict[str, Any] = field(default_factory=dict)

    def direction(self, is_forward: bool) -> StreamDirection:
        return self.client if is_forward else self.server

    @property
    def anomalies(self) -> dict[str, int]:
        merged = dict(self.client.anomalies)
        for name, count in self.server.anomalies.items():
            merged[name] = merged.get(name, 0) + count
        return merged

    @property
    def suspicious(self) -> bool:
        return any(name in SUSPICIOUS_TCP_ANOMALIES for name in self.anomalies)


DataCallback = Callable[[TcpStream, bool, bytes], None]
StreamCallback = Callable[[TcpStream], None]


class TcpReassembler:
    """Keep one TcpStream per live TCP flow and reassemble its payload."""

    def __init__(
        self,
        overlap_policy: str = OVERLAP_FIRST,
        max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
        max_window_bytes: int = DEFAULT_MAX_WINDOW_BYTES,
        on_data: Optional[DataCallback] = None,
        on_stream_end: Optional[StreamCallback] = None,
        keep_finished_streams: bool = False,
    ):
        if overlap_policy not in OVERLAP_POLICIES:
            raise ValueError(f"unknown overlap policy: {overlap_policy}")
        if max_stream_bytes < 0 or max_window_bytes <= 0:
            raise ValueError("stream limits must be positive")
        self.overlap_policy = overlap_policy
        self.max_stream_bytes = max_stream_bytes
        self.max_window_bytes = max_window_bytes
        self.on_data = on_data
        self.on_stream_end = on_stream_end
        self.keep_finished_streams = keep_finished_streams

        self.streams: dict[Any, TcpStream] = {}
        self.finished_streams: list[TcpStream] = []
        self._carried_seq: dict[Any, tuple[Optional[int], Optional[int]]] = {}

        self.streams_created = 0
        self.streams_finished = 0
        self.bytes_assembled = 0
        self.anomaly_counts: dict[str, int] = {}

    def process(self, flow, packet, is_forward: bool) -> None:
        """FlowManager on_packet hook: feed one packet of a flow."""
        if flow.protocol != "TCP":
            return
        flags = getattr(packet, "tcp_flags", None)
        seq = getattr(packet, "tcp_seq", None)
        if flags is None or seq is None:
            return

        stream = self._stream_for(flow)
        direction = stream.direction(is_forward)
        for anomaly in getattr(packet, "defrag_anomalies", ()) or ():
            direction.mark(anomaly)
        data_seq = seq
        if flags & TCP_SYN:
            # SYN uses one sequence number; data starts right after it.
            data_seq = (seq + 1) % SEQ_SPACE
            if direction.base_seq is None:
                direction.base_seq = data_seq

        payload = getattr(packet, "payload", b"") or b""
        if not payload:
            return
        if flags & TCP_RST:
            # Endpoints never deliver RST payload to the application.
            direction.mark(TCP_RST_PAYLOAD)
            direction.dropped_bytes += len(payload)
            return

        chunk = direction.add_segment(
            data_seq,
            payload,
            self.overlap_policy,
            self.max_stream_bytes,
            self.max_window_bytes,
        )
        if chunk:
            self.bytes_assembled += len(chunk)
            if self.on_data is not None:
                self.on_data(stream, is_forward, chunk)

    def _stream_for(self, flow) -> TcpStream:
        stream = self.streams.get(flow.key)
        if stream is not None and stream.flow is not flow:
            # The flow was replaced without on_flow_end being wired up.
            del self.streams[flow.key]
            self._finish(stream)
            stream = None
        if stream is None:
            stream = TcpStream(flow)
            carried = self._carried_seq.pop(flow.key, None)
            if carried is not None and getattr(flow, "is_continuation", False):
                stream.client.base_seq, stream.server.base_seq = carried
            self.streams[flow.key] = stream
            self.streams_created += 1
        return stream

    def close_flow(self, flow) -> Optional[TcpStream]:
        """FlowManager on_flow_end hook: finish the stream of an ended flow."""
        stream = self.streams.get(flow.key)
        if stream is None or stream.flow is not flow:
            return None
        del self.streams[flow.key]
        if getattr(flow, "termination_reason", None) == ACTIVE_TIMEOUT_REASON:
            # The next flow continues this connection: keep the sequence position.
            self._carried_seq[flow.key] = (stream.client.next_seq, stream.server.next_seq)
        self._finish(stream)
        return stream

    def _finish(self, stream: TcpStream) -> None:
        stream.client.finish()
        stream.server.finish()
        stream.closed = True
        self.streams_finished += 1
        for name, count in stream.anomalies.items():
            self.anomaly_counts[name] = self.anomaly_counts.get(name, 0) + count
        if self.keep_finished_streams:
            self.finished_streams.append(stream)
        if self.on_stream_end is not None:
            self.on_stream_end(stream)

    def close_all(self) -> list[TcpStream]:
        streams = list(self.streams.values())
        self.streams.clear()
        for stream in streams:
            self._finish(stream)
        self._carried_seq.clear()
        return streams

    def statistics(self) -> dict[str, int]:
        return {
            "streams": self.streams_created,
            "active_streams": len(self.streams),
            "finished_streams": self.streams_finished,
            "bytes_assembled": self.bytes_assembled,
        }
