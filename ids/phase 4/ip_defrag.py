"""Phase 4 IPv4 fragment reassembly (RFC 791, RFC 815, RFC 1858).

Runs on raw Ethernet frames, before the Phase 2 decoder:

    PCAP / live source -> IpDefragmenter -> PacketDecoder -> FlowManager

Frames that are not IPv4 fragments pass through untouched. Fragments are
buffered until the whole datagram is present, then one rebuilt frame is
returned, so the decoder and flow manager only ever see complete datagrams.
"""

import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Optional

from sparse_buffer import OVERLAP_FIRST, OVERLAP_POLICIES, SparseBuffer


ETHERNET_HEADER_LENGTH = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = {0x8100, 0x88A8, 0x9100}
IP_FLAG_DF = 0x4000
IP_FLAG_MF = 0x2000
IP_OFFSET_MASK = 0x1FFF
MAX_IP_PACKET = 65535

# Smallest header the first fragment must carry (RFC 1858 tiny fragment).
MIN_TRANSPORT_HEADER = {6: 20, 17: 8, 1: 8}

FRAG_OVERLAP = "FRAG_OVERLAP"
FRAG_OVERLAP_CONFLICT = "FRAG_OVERLAP_CONFLICT"
FRAG_DUPLICATE = "FRAG_DUPLICATE"
FRAG_TINY_FIRST = "FRAG_TINY_FIRST"
FRAG_TOO_LARGE = "FRAG_TOO_LARGE"
FRAG_BAD_LENGTH = "FRAG_BAD_LENGTH"
FRAG_TOO_MANY = "FRAG_TOO_MANY"
FRAG_TABLE_FULL = "FRAG_TABLE_FULL"
FRAG_TIMEOUT = "FRAG_TIMEOUT"

DEFAULT_FRAGMENT_TIMEOUT = 30.0
DEFAULT_MAX_DATAGRAMS = 1024
DEFAULT_MAX_FRAGMENTS = 64
DEFAULT_SWEEP_INTERVAL = 1.0

FragmentKey = tuple[bytes, bytes, int, int]


@dataclass
class Ipv4Frame:
    """Header fields read from a raw frame that carries IPv4."""

    link_header: bytes
    ip_header: bytes
    payload: bytes
    src: bytes
    dst: bytes
    protocol: int
    ip_id: int
    flags_offset: int

    @property
    def offset_bytes(self) -> int:
        return (self.flags_offset & IP_OFFSET_MASK) * 8

    @property
    def more_fragments(self) -> bool:
        return bool(self.flags_offset & IP_FLAG_MF)

    @property
    def is_fragment(self) -> bool:
        return self.more_fragments or self.offset_bytes != 0

    @property
    def key(self) -> FragmentKey:
        return self.src, self.dst, self.protocol, self.ip_id


@dataclass
class DefragOutput:
    """A frame ready for the decoder (original or rebuilt from fragments)."""

    timestamp: float
    frame: bytes
    capture_length: Optional[int]
    wire_length: Optional[int]
    fragment_count: int = 0
    anomalies: tuple[str, ...] = ()


@dataclass
class DefragEvent:
    """One anomaly seen while reassembling fragments."""

    timestamp: float
    anomaly: str
    src: str
    dst: str
    protocol: int
    ip_id: int
    detail: str = ""

    def summary(self) -> str:
        return (
            f"{self.anomaly} {self.src} -> {self.dst} proto={self.protocol} "
            f"ip_id={self.ip_id} {self.detail}".rstrip()
        )


@dataclass
class FragmentDatagram:
    """Fragments of one datagram collected so far."""

    key: FragmentKey
    first_seen: float
    last_seen: float
    buffer: SparseBuffer = field(default_factory=SparseBuffer)
    link_header: Optional[bytes] = None
    ip_header: Optional[bytes] = None
    payload_length: Optional[int] = None
    fragment_count: int = 0
    anomalies: list[str] = field(default_factory=list)

    def mark(self, anomaly: str) -> bool:
        """Record an anomaly once; return True the first time."""
        if anomaly in self.anomalies:
            return False
        self.anomalies.append(anomaly)
        return True

    @property
    def is_complete(self) -> bool:
        return (
            self.ip_header is not None
            and self.payload_length is not None
            and self.buffer.contiguous_end(0) >= self.payload_length
        )


def ip_to_text(address: bytes) -> str:
    return ".".join(str(byte) for byte in address)


def ipv4_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def parse_ipv4_frame(raw: bytes) -> Optional[Ipv4Frame]:
    """Read the Ethernet (+VLAN) and IPv4 headers without decoding transport."""
    if len(raw) < ETHERNET_HEADER_LENGTH:
        return None
    position = 12
    ethertype = struct.unpack("!H", raw[position:position + 2])[0]
    position += 2
    while ethertype in ETHERTYPE_VLAN and len(raw) >= position + 4:
        ethertype = struct.unpack("!H", raw[position + 2:position + 4])[0]
        position += 4
    if ethertype != ETHERTYPE_IPV4 or len(raw) < position + 20:
        return None

    version_ihl = raw[position]
    header_length = (version_ihl & 0x0F) * 4
    if version_ihl >> 4 != 4 or header_length < 20 or len(raw) < position + header_length:
        return None
    total_length, ip_id, flags_offset = struct.unpack(
        "!HHH", raw[position + 2:position + 8]
    )
    end = position + total_length if total_length >= header_length else len(raw)
    return Ipv4Frame(
        link_header=raw[:position],
        ip_header=raw[position:position + header_length],
        payload=raw[position + header_length:min(end, len(raw))],
        src=raw[position + 12:position + 16],
        dst=raw[position + 16:position + 20],
        protocol=raw[position + 9],
        ip_id=ip_id,
        flags_offset=flags_offset,
    )


def build_reassembled_frame(datagram: FragmentDatagram) -> bytes:
    """Rebuild one unfragmented frame from the first fragment's headers."""
    payload = bytes(datagram.buffer.data[:datagram.payload_length])
    header = bytearray(datagram.ip_header)
    flags = struct.unpack("!H", header[6:8])[0] & IP_FLAG_DF
    struct.pack_into("!H", header, 2, len(header) + len(payload))
    struct.pack_into("!H", header, 6, flags)
    struct.pack_into("!H", header, 10, 0)
    struct.pack_into("!H", header, 10, ipv4_checksum(bytes(header)))
    return datagram.link_header + bytes(header) + payload


AnomalyCallback = Callable[[DefragEvent], None]


class IpDefragmenter:
    """Reassemble IPv4 fragments from raw frames."""

    def __init__(
        self,
        timeout: float = DEFAULT_FRAGMENT_TIMEOUT,
        overlap_policy: str = OVERLAP_FIRST,
        max_datagrams: int = DEFAULT_MAX_DATAGRAMS,
        max_fragments: int = DEFAULT_MAX_FRAGMENTS,
        sweep_interval: float = DEFAULT_SWEEP_INTERVAL,
        on_anomaly: Optional[AnomalyCallback] = None,
    ):
        if timeout <= 0 or sweep_interval <= 0:
            raise ValueError("timeout and sweep_interval must be greater than zero")
        if overlap_policy not in OVERLAP_POLICIES:
            raise ValueError(f"unknown overlap policy: {overlap_policy}")
        if max_datagrams < 1 or max_fragments < 1:
            raise ValueError("max_datagrams and max_fragments must be at least 1")
        self.timeout = timeout
        self.overlap_policy = overlap_policy
        self.max_datagrams = max_datagrams
        self.max_fragments = max_fragments
        self.sweep_interval = sweep_interval
        self.on_anomaly = on_anomaly

        self.datagrams: dict[FragmentKey, FragmentDatagram] = {}
        self._last_sweep: Optional[float] = None

        self.frames_seen = 0
        self.fragments_seen = 0
        self.datagrams_reassembled = 0
        self.datagrams_dropped = 0
        self.anomaly_counts: dict[str, int] = {}

    def process(
        self,
        timestamp: float,
        raw_frame: bytes,
        capture_length: Optional[int] = None,
        wire_length: Optional[int] = None,
    ) -> Optional[DefragOutput]:
        """Return the frame to decode now, or None while fragments are pending."""
        self.frames_seen += 1
        self._maybe_sweep(timestamp)
        frame = parse_ipv4_frame(raw_frame)
        if frame is None or not frame.is_fragment:
            return DefragOutput(timestamp, raw_frame, capture_length, wire_length)

        self.fragments_seen += 1
        datagram = self.datagrams.get(frame.key)
        if datagram is None:
            if len(self.datagrams) >= self.max_datagrams:
                self._report(timestamp, frame.key, FRAG_TABLE_FULL, "fragment dropped")
                return None
            datagram = FragmentDatagram(frame.key, timestamp, timestamp)
            self.datagrams[frame.key] = datagram
        datagram.last_seen = timestamp

        if not self._add_fragment(datagram, frame, timestamp):
            return None
        if not datagram.is_complete:
            return None

        del self.datagrams[frame.key]
        rebuilt = build_reassembled_frame(datagram)
        self.datagrams_reassembled += 1
        return DefragOutput(
            timestamp=timestamp,
            frame=rebuilt,
            capture_length=len(rebuilt),
            wire_length=len(rebuilt),
            fragment_count=datagram.fragment_count,
            anomalies=tuple(datagram.anomalies),
        )

    def _add_fragment(self, datagram: FragmentDatagram, frame: Ipv4Frame, timestamp: float) -> bool:
        """Store one fragment. Return False if the datagram had to be dropped."""
        datagram.fragment_count += 1
        if datagram.fragment_count > self.max_fragments:
            self._drop(datagram, timestamp, FRAG_TOO_MANY, f"more than {self.max_fragments} fragments")
            return False

        offset = frame.offset_bytes
        payload = frame.payload
        end = offset + len(payload)
        if end > MAX_IP_PACKET - len(frame.ip_header):
            self._drop(datagram, timestamp, FRAG_TOO_LARGE, f"datagram end={end} bytes")
            return False

        if frame.more_fragments and len(payload) % 8:
            self._mark(datagram, timestamp, FRAG_BAD_LENGTH, "non-last fragment length not multiple of 8")
        if not frame.more_fragments:
            if datagram.payload_length is not None and datagram.payload_length != end:
                self._mark(datagram, timestamp, FRAG_BAD_LENGTH, "conflicting last fragment")
            else:
                datagram.payload_length = end
        if offset == 0:
            datagram.link_header = frame.link_header
            datagram.ip_header = frame.ip_header
            minimum = MIN_TRANSPORT_HEADER.get(frame.protocol, 0)
            if len(payload) < minimum:
                self._mark(datagram, timestamp, FRAG_TINY_FIRST, f"first fragment carries {len(payload)} bytes")

        result = datagram.buffer.write(offset, payload, self.overlap_policy)
        if result.conflict_bytes:
            self._mark(datagram, timestamp, FRAG_OVERLAP_CONFLICT, f"{result.conflict_bytes} bytes differ at offset {offset}")
        elif result.overlap_bytes == len(payload):
            self._mark(datagram, timestamp, FRAG_DUPLICATE, f"offset {offset}")
        elif result.overlap_bytes:
            self._mark(datagram, timestamp, FRAG_OVERLAP, f"{result.overlap_bytes} bytes at offset {offset}")

        if datagram.payload_length is not None and datagram.buffer.covered_bytes and (
            datagram.buffer.ranges[-1][1] > datagram.payload_length
        ):
            self._mark(datagram, timestamp, FRAG_BAD_LENGTH, "data beyond last fragment")
        return True

    def _mark(self, datagram: FragmentDatagram, timestamp: float, anomaly: str, detail: str) -> None:
        if datagram.mark(anomaly):
            self._report(timestamp, datagram.key, anomaly, detail)

    def _drop(self, datagram: FragmentDatagram, timestamp: float, anomaly: str, detail: str) -> None:
        self._mark(datagram, timestamp, anomaly, detail)
        self.datagrams.pop(datagram.key, None)
        self.datagrams_dropped += 1

    def _report(self, timestamp: float, key: FragmentKey, anomaly: str, detail: str) -> None:
        self.anomaly_counts[anomaly] = self.anomaly_counts.get(anomaly, 0) + 1
        if self.on_anomaly is not None:
            src, dst, protocol, ip_id = key
            self.on_anomaly(
                DefragEvent(timestamp, anomaly, ip_to_text(src), ip_to_text(dst), protocol, ip_id, detail)
            )

    def _maybe_sweep(self, timestamp: float) -> None:
        if self._last_sweep is None:
            self._last_sweep = timestamp
        elif timestamp - self._last_sweep >= self.sweep_interval:
            self.expire(timestamp)

    def expire(self, timestamp: float) -> int:
        """Drop datagrams whose first fragment is older than the timeout."""
        self._last_sweep = timestamp
        expired = [
            datagram
            for datagram in self.datagrams.values()
            if timestamp - datagram.first_seen >= self.timeout
        ]
        for datagram in expired:
            missing = self._missing_description(datagram)
            self._drop(datagram, timestamp, FRAG_TIMEOUT, missing)
        return len(expired)

    def flush(self, timestamp: Optional[float] = None) -> int:
        """End of capture: every incomplete datagram is dropped as a timeout."""
        pending = list(self.datagrams.values())
        for datagram in pending:
            self._drop(
                datagram,
                datagram.last_seen if timestamp is None else timestamp,
                FRAG_TIMEOUT,
                self._missing_description(datagram),
            )
        return len(pending)

    @staticmethod
    def _missing_description(datagram: FragmentDatagram) -> str:
        if datagram.ip_header is None:
            return "first fragment missing"
        if datagram.payload_length is None:
            return "last fragment missing"
        holes = datagram.buffer.gaps(0, datagram.payload_length)
        return "missing bytes " + ",".join(f"{start}-{end}" for start, end in holes)

    def statistics(self) -> dict[str, int]:
        return {
            "frames": self.frames_seen,
            "fragments": self.fragments_seen,
            "reassembled": self.datagrams_reassembled,
            "dropped": self.datagrams_dropped,
            "pending": len(self.datagrams),
        }
