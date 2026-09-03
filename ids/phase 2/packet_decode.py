#!/usr/bin/env python3

"""
Phase 2 - Packet Decoder

Responsibilities:
    1. Read packets from a PCAP file.
    2. Decode Ethernet.
    3. Decode IPv4.
    4. Decode TCP / UDP / ICMP.
       Non-IPv4 packets are still reported and ignored for
       transport decoding in Phase 2.
    5. Extract:
         - capture metadata
         - MAC addresses
         - IP addresses
         - protocol
         - ports
         - TCP sequence number
         - TCP acknowledgement number
         - TCP flags
         - TCP window
         - TCP options
         - IP fragmentation information
         - checksums
         - ICMP metadata
         - payload
         - 5-tuple
         - IP fragment key
         - Packet abstraction for Phase 3 Flow Manager / Reassembly

Important:
    Phase 2 ONLY decodes packets.

    It does NOT implement:
        - Flow tracking
        - IP reassembly
        - TCP reassembly
        - Normalization
        - Detection
        - Alerting

Capture metadata:
    capture_length:
        Number of bytes actually stored in the PCAP packet record.
        This corresponds to the PCAP incl_len field.

    wire_length:
        Original packet length on the wire.
        This corresponds to the PCAP orig_len field.

Run:
    python3 phase2_decode.py capture.pcap

Example:
    python3 phase2_decode.py capture.pcap --limit 20
"""

import argparse
import socket
import struct
import sys
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone

import dpkt


# ============================================================
# Constants
# ============================================================

# Chuyển TCP Flags từ dạng bit/hex sang tên dễ đọc
TCP_FLAGS = {
    dpkt.tcp.TH_FIN: "FIN",
    dpkt.tcp.TH_SYN: "SYN",
    dpkt.tcp.TH_RST: "RST",
    dpkt.tcp.TH_PUSH: "PSH",
    dpkt.tcp.TH_ACK: "ACK",
    dpkt.tcp.TH_URG: "URG",
    dpkt.tcp.TH_ECE: "ECE",
    dpkt.tcp.TH_CWR: "CWR",
}


# ============================================================
# Utility Functions
# ============================================================

def mac_to_string(mac):
    """
    Convert binary MAC address to readable string.
    """

    if not mac:
        return "unknown"

    return ":".join(
        f"{byte:02x}"
        for byte in mac
    )


def ip_to_string(ip):
    """
    Convert binary IPv4 address to readable string.
    """

    try:
        return socket.inet_ntoa(ip)

    except (OSError, TypeError):
        return "unknown"


def format_tcp_flags(flags):
    """
    Convert TCP flag bitmask to readable string.
    """

    names = []

    for flag_value, flag_name in TCP_FLAGS.items():

        if flags & flag_value:
            names.append(flag_name)

    if not names:
        return "NONE"

    return ",".join(names)


def hex_preview(data, length=64):
    """
    Return a small hexadecimal preview of payload.
    """

    if not data:
        return ""

    preview = data[:length]

    hex_data = " ".join(
        f"{byte:02x}"
        for byte in preview
    )

    if len(data) > length:
        hex_data += " ..."

    return hex_data


def ascii_preview(data, length=128):
    """
    Return readable ASCII preview.

    Non-printable bytes are replaced with '.'
    """

    if not data:
        return ""

    preview = data[:length]

    result = []

    for byte in preview:

        if 32 <= byte <= 126:
            result.append(chr(byte))

        else:
            result.append(".")

    text = "".join(result)

    if len(data) > length:
        text += " ..."

    return text

def format_timestamp(timestamp):
    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S.%f")

# ============================================================
# Protocol Name
# ============================================================

def protocol_name(protocol):

    if protocol == dpkt.ip.IP_PROTO_TCP:
        return "TCP"

    if protocol == dpkt.ip.IP_PROTO_UDP:
        return "UDP"

    if protocol == dpkt.ip.IP_PROTO_ICMP:
        return "ICMP"

    return f"OTHER({protocol})"


# ============================================================
# PCAP Reader
# ============================================================

def read_pcap_packets(file):
    """
    Read packets directly from a classic PCAP file.

    This function reads the PCAP packet record header directly
    so that both incl_len and orig_len are available.

    Structure of a pcap file:
    ┌───────────────────────────────────────────────────────┐
    │              Global Header (24 bytes)                 │
    ├───────────────────────────────────────────────────────┤
    │  Packet Header 1 (16 bytes)                           │
    ├───────────────────────────────┐                       │
    │  Packet Data 1 (Raw Payload)  │──> Gói tin mạng thứ 1 │
    ├───────────────────────────────┴───────────────────────┤
    │  Packet Header 2 (16 bytes)                           │
    ├───────────────────────────────┐                       │
    │  Packet Data 2 (Raw Payload)  │──> Gói tin mạng thứ 2 │
    ├───────────────────────────────┴───────────────────────┤
    │  ... (Tiếp tục cho đến hết file)                      │
    └───────────────────────────────────────────────────────┘
    PCAP global header (24 bytes):

        magic_number;   /* 4 bytes: Nhận diện định dạng file và tính Endian */
        version_major;  /* 2 bytes: Phiên bản chính (Thường là 2) */
        version_minor;  /* 2 bytes: Phiên bản phụ (Thường là 4) */
        thiszone;       /* 4 bytes: Múi giờ gmt (Thường là 0) */
        sigfigs;        /* 4 bytes: Độ chính xác timestamp (Thường là 0) */
        snaplen;        /* 4 bytes: Chiều dài tối đa của gói tin được chụp */
        network;        /* 4 bytes: Loại tầng liên kết dữ liệu (Data Link Type) */


    PCAP packet record header (16 bytes):

        ts_sec;   /* 4 bytes: Dấu thời gian (giây) */
        ts_usec;  /* 4 bytes: Dấu thời gian (micro-giây hoặc nano-giây) */
        incl_len; /* 4 bytes: Số byte dữ liệu thực tế được lưu vào file */
        orig_len; /* 4 bytes: Số byte thực tế của gói tin khi chạy trên mạng */

    Returns:

        timestamp
        raw_packet
        capture_length
        wire_length

    Where:

        capture_length = incl_len
        wire_length    = orig_len

    Important:
        This function is for classic PCAP format.
        It is NOT a PCAP-NG parser.
    """

    # --------------------------------------------------------
    # Read PCAP global header
    # --------------------------------------------------------

    global_header = file.read(24)

    if len(global_header) != 24:

        raise ValueError(
            "Invalid or truncated PCAP global header"
        )

    # --------------------------------------------------------
    # Detect PCAP byte order and timestamp precision
    # --------------------------------------------------------

    magic = global_header[:4]

    # Classic PCAP, microsecond precision, little endian
    if magic == b"\xd4\xc3\xb2\xa1":

        endian = "<"

    # Classic PCAP, microsecond precision, big endian
    elif magic == b"\xa1\xb2\xc3\xd4":

        endian = ">"

    # Classic PCAP, nanosecond precision, little endian
    elif magic == b"\x4d\x3c\xb2\xa1":

        endian = "<"

    # Classic PCAP, nanosecond precision, big endian
    elif magic == b"\xa1\xb2\x3c\x4d":

        endian = ">"

    else:

        raise ValueError(
            "Unsupported PCAP format or invalid PCAP magic number"
        )

    # Nanosecond PCAP uses the same packet record structure.
    #
    # The timestamp fraction is converted below using the
    # appropriate divisor.

    nanosecond_precision = magic in (
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    )

    timestamp_divisor = (
        1_000_000_000
        if nanosecond_precision
        else 1_000_000
    )

    # --------------------------------------------------------
    # Read every packet record 
    # --------------------------------------------------------

    while True:

        packet_header = file.read(16)

        # Normal end of PCAP
        if not packet_header:
            break

        if len(packet_header) != 16:

            raise ValueError(
                "Truncated PCAP packet header"
            )

        # nhận vào chuỗi byte thô và sắp xếp theo định dạng endian để giải nén thành các trường dữ liệu
        (
            ts_sec,
            ts_fraction,
            incl_len,
            orig_len,
        ) = struct.unpack(
            endian + "IIII",
            packet_header
        )

        # ----------------------------------------------------
        # Read exactly incl_len bytes
        # ----------------------------------------------------

        raw_packet = file.read(
            incl_len
        )

        if len(raw_packet) != incl_len:

            raise ValueError(
                "Truncated PCAP packet data"
            )

        # ----------------------------------------------------
        # Build timestamp
        # ----------------------------------------------------

        timestamp = (
            ts_sec
            + (
                ts_fraction
                / timestamp_divisor
            )
        )

        # ----------------------------------------------------
        # Yield yield trả từng kết quả một, 
        # tạm dừng hàm và giữ trạng thái để lần iteration tiếp theo tiếp tục từ chỗ đã dừng
        # ----------------------------------------------------

        yield (
            timestamp,
            raw_packet,
            incl_len,
            orig_len,
        )


# ============================================================
# Packet Object
# ============================================================

@dataclass
class Packet:
    """
    Normalized packet abstraction used by later IDS phases.

    Phase 2 only creates this object.

    Flow tracking, reassembly, normalization and detection
    are NOT implemented here.
    """

    # --------------------------------------------------------
    # Capture metadata
    # --------------------------------------------------------

    timestamp: float

    # Number of bytes actually captured/stored in PCAP.
    #
    # PCAP field:
    #     incl_len
    #
    capture_length: Optional[int] = None

    # Original packet size on the wire.
    #
    # PCAP field:
    #     orig_len
    #
    wire_length: Optional[int] = None

    # --------------------------------------------------------
    # Ethernet
    # --------------------------------------------------------

    src_mac: str = "unknown"
    dst_mac: str = "unknown"
    ethertype: Optional[int] = None

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    ip_protocol: Optional[str] = None
    ip_protocol_number: Optional[int] = None

    ip_ttl: Optional[int] = None
    ip_id: Optional[int] = None

    ip_header_length: Optional[int] = None
    ip_total_length: Optional[int] = None

    ip_checksum: Optional[int] = None

    # Raw offset value from IPv4 header.
    # Unit = 8-byte blocks.
    fragment_offset: int = 0

    # Offset converted to bytes.
    fragment_offset_bytes: int = 0

    more_fragments: bool = False
    dont_fragment: bool = False

    # IPv4 options preserved for future analysis.
    ip_options: bytes = field(default_factory=bytes)

    # Key required by IP Fragment Reassembly.
    #
    # (src_ip, dst_ip, protocol_number, ip_id)
    ip_fragment_key: Optional[tuple] = None

    # --------------------------------------------------------
    # Transport
    # --------------------------------------------------------

    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None

    tcp_flags: Optional[int] = None
    tcp_flags_text: Optional[str] = None

    tcp_window: Optional[int] = None
    tcp_header_length: Optional[int] = None

    tcp_checksum: Optional[int] = None
    tcp_urgent_pointer: Optional[int] = None

    tcp_options: bytes = field(default_factory=bytes)

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    udp_length: Optional[int] = None
    udp_checksum: Optional[int] = None

    # --------------------------------------------------------
    # ICMP
    # --------------------------------------------------------

    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    icmp_checksum: Optional[int] = None

    icmp_identifier: Optional[int] = None
    icmp_sequence: Optional[int] = None

    # --------------------------------------------------------
    # Payload
    # --------------------------------------------------------

    # Normalization belongs to a later phase.
    payload: bytes = field(default_factory=bytes)

    # --------------------------------------------------------
    # Flow
    # --------------------------------------------------------

    # Directional 5-tuple:
    #
    # (src_ip, dst_ip, src_port, dst_port, protocol)
    flow_key: Optional[tuple] = None

    # --------------------------------------------------------
    # Helper methods
    # --------------------------------------------------------

    def payload_length(self) -> int:
        return len(self.payload)

    def is_ip_fragment(self) -> bool:
        """
        Return True when this packet belongs to an IPv4
        fragmented datagram.
        """

        return (
            self.fragment_offset != 0
            or self.more_fragments
        )

    def is_first_fragment(self) -> bool:
        """
        Return True when this is the first IP fragment.
        """

        return self.fragment_offset == 0

    def summary(self) -> str:

        return (
            f"{self.ip_protocol or 'NON-IP'} "
            f"{self.src_ip or '-'}:{self.src_port or '-'} -> "
            f"{self.dst_ip or '-'}:{self.dst_port or '-'} "
            f"payload={len(self.payload)}"
        )


# ============================================================
# Packet Decoder
# ============================================================

class PacketDecoder:

    def __init__(self):

        self.total_packets = 0

        self.ipv4_packets = 0

        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0

        self.fragmented_packets = 0

        self.other_packets = 0

        # Flow Manager / Reassembly.
        self.packets = []

    # ========================================================
    # Packet Object factory
    # ========================================================

    def _ethernet_fields(self, eth):

        if eth is None:

            return {
                "src_mac": "unknown",
                "dst_mac": "unknown",
                "ethertype": None,
            }

        return {
            "src_mac": mac_to_string(eth.src),
            "dst_mac": mac_to_string(eth.dst),
            "ethertype": eth.type,
        }

    def _ipv4_fields(
        self,
        ip,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port
    ):

        if ip is None:

            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,

                "ip_protocol": protocol,
                "ip_protocol_number": None,

                "ip_ttl": None,
                "ip_id": None,

                "ip_header_length": None,
                "ip_total_length": None,

                "ip_checksum": None,

                "fragment_offset": 0,
                "fragment_offset_bytes": 0,

                "more_fragments": False,
                "dont_fragment": False,

                "ip_options": b"",
                "ip_fragment_key": None,

                "src_port": src_port,
                "dst_port": dst_port,
            }

        fragment_offset = (
            ip.off & dpkt.ip.IP_OFFMASK
        )

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,

            "ip_protocol": protocol,
            "ip_protocol_number": ip.p,

            "ip_ttl": ip.ttl,
            "ip_id": ip.id,

            "ip_header_length": ip.hl * 4,
            "ip_total_length": ip.len,

            "ip_checksum": ip.sum,

            # IPv4 fragment offset:
            # value is expressed in 8-byte units.
            "fragment_offset": fragment_offset,

            # Converted to bytes for reassembly.
            "fragment_offset_bytes": (
                fragment_offset * 8
            ),

            "more_fragments": bool(
                ip.off & dpkt.ip.IP_MF
            ),

            "dont_fragment": bool(
                ip.off & dpkt.ip.IP_DF
            ),

            "ip_options": bytes(
                getattr(ip, "opts", b"")
            ),

            # RFC-style identification key:
            #
            # src + dst + protocol + identification
            "ip_fragment_key": (
                src_ip,
                dst_ip,
                ip.p,
                ip.id,
            ),

            "src_port": src_port,
            "dst_port": dst_port,
        }

    def _transport_fields(
        self,
        tcp,
        udp,
        icmp
    ):

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        if tcp is not None:

            return {

                "tcp_seq": tcp.seq,
                "tcp_ack": tcp.ack,

                "tcp_flags": tcp.flags,
                "tcp_flags_text": format_tcp_flags(
                    tcp.flags
                ),

                "tcp_window": tcp.win,

                "tcp_header_length": (
                    tcp.off * 4
                ),

                "tcp_checksum": tcp.sum,

                "tcp_urgent_pointer": tcp.urp,

                "tcp_options": bytes(
                    getattr(
                        tcp,
                        "opts",
                        b""
                    )
                ),

                "udp_length": None,
                "udp_checksum": None,

                "icmp_type": None,
                "icmp_code": None,
                "icmp_checksum": None,
                "icmp_identifier": None,
                "icmp_sequence": None,
            }

        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        if udp is not None:

            return {

                "tcp_seq": None,
                "tcp_ack": None,

                "tcp_flags": None,
                "tcp_flags_text": None,

                "tcp_window": None,
                "tcp_header_length": None,

                "tcp_checksum": None,
                "tcp_urgent_pointer": None,
                "tcp_options": b"",

                "udp_length": udp.ulen,
                "udp_checksum": udp.sum,

                "icmp_type": None,
                "icmp_code": None,
                "icmp_checksum": None,
                "icmp_identifier": None,
                "icmp_sequence": None,
            }

        # ----------------------------------------------------
        # ICMP
        # ----------------------------------------------------

        if icmp is not None:

            identifier = None
            sequence = None

            icmp_data = getattr(
                icmp,
                "data",
                None
            )

            if isinstance(
                icmp_data,
                dpkt.icmp.ICMP.Echo
            ):

                identifier = icmp_data.id
                sequence = icmp_data.seq

            return {

                "tcp_seq": None,
                "tcp_ack": None,

                "tcp_flags": None,
                "tcp_flags_text": None,

                "tcp_window": None,
                "tcp_header_length": None,

                "tcp_checksum": None,
                "tcp_urgent_pointer": None,

                "tcp_options": b"",

                "udp_length": None,
                "udp_checksum": None,

                "icmp_type": icmp.type,
                "icmp_code": icmp.code,
                "icmp_checksum": icmp.sum,

                "icmp_identifier": identifier,
                "icmp_sequence": sequence,
            }

        # ----------------------------------------------------
        # Unknown / non-transport
        # ----------------------------------------------------

        return {

            "tcp_seq": None,
            "tcp_ack": None,

            "tcp_flags": None,
            "tcp_flags_text": None,

            "tcp_window": None,
            "tcp_header_length": None,

            "tcp_checksum": None,
            "tcp_urgent_pointer": None,

            "tcp_options": b"",

            "udp_length": None,
            "udp_checksum": None,

            "icmp_type": None,
            "icmp_code": None,
            "icmp_checksum": None,

            "icmp_identifier": None,
            "icmp_sequence": None,
        }

    # ========================================================
    # Build Packet
    # ========================================================

    def build_packet(
        self,
        timestamp,
        eth,
        ip,
        protocol,
        src_ip,
        dst_ip,
        src_port=None,
        dst_port=None,
        tcp=None,
        udp=None,
        icmp=None,
        payload=b"",
        flow_key=None,
        capture_length=None,
        wire_length=None,
    ):
        """
        Build the normalized Packet object consumed by Phase 3.

        capture_length:
            Number of bytes actually captured in PCAP.

        wire_length:
            Original packet size from PCAP orig_len.
        """

        packet = Packet(

            timestamp=timestamp,

            # PCAP incl_len
            capture_length=capture_length,

            # PCAP orig_len
            wire_length=wire_length,

            payload=payload,
            flow_key=flow_key,

            **self._ethernet_fields(eth),

            **self._ipv4_fields(
                ip,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            ),

            **self._transport_fields(
                tcp,
                udp,
                icmp,
            ),
        )

        self.packets.append(packet)

        return packet

    # ========================================================
    # Ethernet
    # ========================================================

    def decode_ethernet(
        self,
        raw_packet,
        timestamp=0.0,
        capture_length=None,
        wire_length=None
    ):

        try:

            eth = dpkt.ethernet.Ethernet(
                raw_packet
            )

        except (
            dpkt.dpkt.NeedData,
            dpkt.dpkt.UnpackError
        ):

            print(
                "[!] Invalid Ethernet frame."
            )

            return

        # ----------------------------------------------------
        # Capture length
        # ----------------------------------------------------
        #
        # If capture_length was supplied from the PCAP header,
        # use it.
        #
        # Otherwise fall back to the actual byte count in
        # raw_packet.
        #

        if capture_length is None:

            capture_length = len(
                raw_packet
            )

        print()
        print("=" * 80)

        print(
            f"Packet #{self.total_packets}"
        )

        print("=" * 80)
        print(
            f"Timestamp       : {format_timestamp(timestamp)}"
        )

        # ----------------------------------------------------
        # Ethernet header
        # ----------------------------------------------------

        print("Ethernet")
        print("-" * 80)

        print(
            f"  Source MAC      : "
            f"{mac_to_string(eth.src)}"
        )

        print(
            f"  Destination MAC : "
            f"{mac_to_string(eth.dst)}"
        )

        print(
            f"  EtherType       : "
            f"0x{eth.type:04x}"
        )

        print(
            f"  Capture Length  : "
            f"{capture_length} bytes"
        )

        if wire_length is not None:

            print(
                f"  Wire Length     : "
                f"{wire_length} bytes"
            )

        # ----------------------------------------------------
        # Only process IPv4 for Phase 2
        # ----------------------------------------------------

        if not isinstance(
            eth.data,
            dpkt.ip.IP
        ):

            self.other_packets += 1

            print()
            print(
                "  Non-IPv4 packet."
            )

            print(
                "  Transport decoder "
                "stops at Ethernet layer."
            )

            return

        self.ipv4_packets += 1

        ip = eth.data

        self.decode_ipv4(
            ip,
            timestamp,
            eth,
            capture_length=capture_length,
            wire_length=wire_length,
        )

    # ========================================================
    # IPv4
    # ========================================================

    def decode_ipv4(
        self,
        ip,
        timestamp=0.0,
        eth=None,
        capture_length=None,
        wire_length=None,
    ):

        src_ip = ip_to_string(
            ip.src
        )

        dst_ip = ip_to_string(
            ip.dst
        )

        protocol = protocol_name(
            ip.p
        )

        # ----------------------------------------------------
        # IP fragmentation information
        # ----------------------------------------------------

        fragment_offset = (
            ip.off & dpkt.ip.IP_OFFMASK
        )

        fragment_offset_bytes = (
            fragment_offset * 8
        )

        more_fragments = bool(
            ip.off & dpkt.ip.IP_MF
        )

        dont_fragment = bool(
            ip.off & dpkt.ip.IP_DF
        )

        is_fragment = (
            fragment_offset != 0
            or more_fragments
        )

        if is_fragment:

            self.fragmented_packets += 1

        print()
        print("IPv4")
        print("-" * 80)
        print(f"Timestamp       : {format_timestamp(timestamp)}")

        print(
            f"  Source IP       : "
            f"{src_ip}"
        )

        print(
            f"  Destination IP  : "
            f"{dst_ip}"
        )

        print(
            f"  Protocol        : "
            f"{protocol}"
        )

        print(
            f"  Protocol Number : "
            f"{ip.p}"
        )

        print(
            f"  TTL             : "
            f"{ip.ttl}"
        )

        print(
            f"  Identification  : "
            f"{ip.id}"
        )

        print(
            f"  Header Length   : "
            f"{ip.hl * 4} bytes"
        )

        print(
            f"  Total Length    : "
            f"{ip.len} bytes"
        )

        print(
            f"  Header Checksum : "
            f"0x{ip.sum:04x}"
        )

        print(
            f"  Fragment Offset : "
            f"{fragment_offset} "
            f"(8-byte units)"
        )

        print(
            f"  Offset Bytes    : "
            f"{fragment_offset_bytes}"
        )

        print(
            f"  More Fragments  : "
            f"{more_fragments}"
        )

        print(
            f"  Don't Fragment  : "
            f"{dont_fragment}"
        )

        # ----------------------------------------------------
        # IP Fragment Key
        # ----------------------------------------------------

        fragment_key = (
            src_ip,
            dst_ip,
            ip.p,
            ip.id,
        )

        print(
            f"  Fragment Key    : "
            f"{fragment_key}"
        )

        # ----------------------------------------------------
        # IMPORTANT:
        #
        # Do NOT discard non-first fragments.
        #
        # They are required by Phase 3 IP reassembly.
        #
        # Only the first fragment normally contains the
        # transport header.
        # ----------------------------------------------------

        if fragment_offset != 0:

            print()
            print(
                "  [!] Non-first IP fragment."
            )

            print(
                "  [!] Transport header is "
                "not decoded here."
            )

            print(
                "  [!] Fragment will still be "
                "stored for Phase 3 reassembly."
            )

            fragment_payload = bytes(
                ip.data
            )

            self.build_packet(
                timestamp=timestamp,
                eth=eth,
                ip=ip,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                payload=fragment_payload,
                flow_key=None,
                capture_length=capture_length,
                wire_length=wire_length,
            )

            print(
                f"  Fragment Payload: "
                f"{len(fragment_payload)} bytes"
            )

            return

        # ----------------------------------------------------
        # Transport protocol
        # ----------------------------------------------------

        if isinstance(
            ip.data,
            dpkt.tcp.TCP
        ):

            self.tcp_packets += 1

            self.decode_tcp(
                src_ip,
                dst_ip,
                ip.data,
                timestamp=timestamp,
                eth=eth,
                ip=ip,
                capture_length=capture_length,
                wire_length=wire_length,
            )

        elif isinstance(
            ip.data,
            dpkt.udp.UDP
        ):

            self.udp_packets += 1

            self.decode_udp(
                src_ip,
                dst_ip,
                ip.data,
                timestamp=timestamp,
                eth=eth,
                ip=ip,
                capture_length=capture_length,
                wire_length=wire_length,
            )

        elif isinstance(
            ip.data,
            dpkt.icmp.ICMP
        ):

            self.icmp_packets += 1

            self.decode_icmp(
                src_ip,
                dst_ip,
                ip.data,
                timestamp=timestamp,
                eth=eth,
                ip=ip,
                capture_length=capture_length,
                wire_length=wire_length,
            )

        else:

            self.other_packets += 1

            unknown_payload = bytes(
                ip.data
            )

            self.build_packet(
                timestamp=timestamp,
                eth=eth,
                ip=ip,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                payload=unknown_payload,
                flow_key=None,
                capture_length=capture_length,
                wire_length=wire_length,
            )

            print()
            print(
                f"  Transport protocol "
                f"not decoded: {protocol}"
            )

    # ========================================================
    # TCP
    # ========================================================

    def decode_tcp(
        self,
        src_ip,
        dst_ip,
        tcp,
        timestamp=0.0,
        eth=None,
        ip=None,
        capture_length=None,
        wire_length=None,
    ):

        payload = bytes(
            tcp.data
        )

        flags = format_tcp_flags(
            tcp.flags
        )

        # ----------------------------------------------------
        # 5-tuple
        # ----------------------------------------------------

        flow_key = (
            src_ip,
            dst_ip,
            tcp.sport,
            tcp.dport,
            "TCP"
        )

        self.build_packet(
            timestamp=timestamp,
            eth=eth,
            ip=ip,
            protocol="TCP",

            src_ip=src_ip,
            dst_ip=dst_ip,

            src_port=tcp.sport,
            dst_port=tcp.dport,

            tcp=tcp,

            payload=payload,

            flow_key=flow_key,

            capture_length=capture_length,
            wire_length=wire_length,
        )

        print()
        print("TCP")
        print("-" * 80)
        print(f"Timestamp       : {format_timestamp(timestamp)}")

        print(
            f"  Source Port      : "
            f"{tcp.sport}"
        )

        print(
            f"  Destination Port : "
            f"{tcp.dport}"
        )

        print(
            f"  Sequence Number  : "
            f"{tcp.seq}"
        )

        print(
            f"  Acknowledgement  : "
            f"{tcp.ack}"
        )

        print(
            f"  Flags            : "
            f"{flags}"
        )

        print(
            f"  Window           : "
            f"{tcp.win}"
        )

        print(
            f"  TCP Header Len   : "
            f"{tcp.off * 4} bytes"
        )

        print(
            f"  Checksum         : "
            f"0x{tcp.sum:04x}"
        )

        print(
            f"  Urgent Pointer   : "
            f"{tcp.urp}"
        )

        print(
            f"  Options Length   : "
            f"{len(getattr(tcp, 'opts', b''))} bytes"
        )

        print(
            f"  Payload Length   : "
            f"{len(payload)} bytes"
        )

        print()
        print("5-TUPLE")
        print("-" * 80)

        print(
            f"  {flow_key}"
        )

        if payload:

            print()
            print("TCP PAYLOAD")
            print("-" * 80)

            print(
                f"  Hex   : "
                f"{hex_preview(payload)}"
            )

            print(
                f"  ASCII : "
                f"{ascii_preview(payload)}"
            )

        else:

            print()
            print(
                "  No TCP payload."
            )

    # ========================================================
    # UDP
    # ========================================================

    def decode_udp(
        self,
        src_ip,
        dst_ip,
        udp,
        timestamp=0.0,
        eth=None,
        ip=None,
        capture_length=None,
        wire_length=None,
    ):

        payload = bytes(
            udp.data
        )

        flow_key = (
            src_ip,
            dst_ip,
            udp.sport,
            udp.dport,
            "UDP"
        )

        self.build_packet(
            timestamp=timestamp,
            eth=eth,
            ip=ip,
            protocol="UDP",

            src_ip=src_ip,
            dst_ip=dst_ip,

            src_port=udp.sport,
            dst_port=udp.dport,

            udp=udp,

            payload=payload,

            flow_key=flow_key,

            capture_length=capture_length,
            wire_length=wire_length,
        )

        print()
        print("UDP")
        print("-" * 80)
        print(f"Timestamp       : {format_timestamp(timestamp)}")
        print(
            f"  Source Port      : "
            f"{udp.sport}"
        )

        print(
            f"  Destination Port : "
            f"{udp.dport}"
        )

        print(
            f"  UDP Length       : "
            f"{udp.ulen}"
        )

        print(
            f"  UDP Checksum     : "
            f"0x{udp.sum:04x}"
        )

        print(
            f"  Payload Length   : "
            f"{len(payload)}"
        )

        print()
        print("5-TUPLE")
        print("-" * 80)

        print(
            f"  {flow_key}"
        )

        if payload:

            print()
            print("UDP PAYLOAD")
            print("-" * 80)

            print(
                f"  Hex   : "
                f"{hex_preview(payload)}"
            )

            print(
                f"  ASCII : "
                f"{ascii_preview(payload)}"
            )

    # ========================================================
    # ICMP
    # ========================================================

    def decode_icmp(
        self,
        src_ip,
        dst_ip,
        icmp,
        timestamp=0.0,
        eth=None,
        ip=None,
        capture_length=None,
        wire_length=None,
    ):

        payload = (
            bytes(icmp.data)
            if getattr(
                icmp,
                "data",
                None
            )
            else b""
        )

        self.build_packet(
            timestamp=timestamp,
            eth=eth,
            ip=ip,
            protocol="ICMP",

            src_ip=src_ip,
            dst_ip=dst_ip,

            icmp=icmp,

            payload=payload,

            flow_key=(
                src_ip,
                dst_ip,
                None,
                None,
                "ICMP"
            ),

            capture_length=capture_length,
            wire_length=wire_length,
        )

        print()
        print("ICMP")
        print("-" * 80)
        print(f"Timestamp       : {format_timestamp(timestamp)}")

        print(
            f"  Source IP      : "
            f"{src_ip}"
        )

        print(
            f"  Destination IP : "
            f"{dst_ip}"
        )

        print(
            f"  Type           : "
            f"{icmp.type}"
        )

        print(
            f"  Code           : "
            f"{icmp.code}"
        )

        print(
            f"  Checksum       : "
            f"0x{icmp.sum:04x}"
        )

        icmp_data = getattr(
            icmp,
            "data",
            None
        )

        if isinstance(
            icmp_data,
            dpkt.icmp.ICMP.Echo
        ):

            print(
                f"  Identifier     : "
                f"{icmp_data.id}"
            )

            print(
                f"  Sequence       : "
                f"{icmp_data.seq}"
            )

        print(
            f"  Payload Length : "
            f"{len(payload)}"
        )

    # ========================================================
    # Statistics
    # ========================================================

    def print_statistics(self):

        print()
        print()
        print("=" * 80)
        print("CAPTURE / DECODING STATISTICS")
        print("=" * 80)

        print(
            f"Total packets      : "
            f"{self.total_packets}"
        )

        print(
            f"IPv4 packets       : "
            f"{self.ipv4_packets}"
        )

        print(
            f"TCP packets        : "
            f"{self.tcp_packets}"
        )

        print(
            f"UDP packets        : "
            f"{self.udp_packets}"
        )

        print(
            f"ICMP packets       : "
            f"{self.icmp_packets}"
        )

        print(
            f"Fragmented packets : "
            f"{self.fragmented_packets}"
        )

        print(
            f"Other packets      : "
            f"{self.other_packets}"
        )

        print(
            f"Packet objects     : "
            f"{len(self.packets)}"
        )

        print("=" * 80)


# ============================================================
# PCAP Processing
# ============================================================

def decode_pcap(
    filename,
    packet_limit=None
):

    decoder = PacketDecoder()

    try:

        with open(
            filename,
            "rb"
        ) as file:

            # ------------------------------------------------
            # Read PCAP packets.
            #
            # Each packet gives us:
            #
            #   raw_packet      -> actual captured bytes
            #   capture_length  -> incl_len
            #   wire_length     -> orig_len
            #
            # ------------------------------------------------

            for (
                timestamp,
                raw_packet,
                capture_length,
                wire_length,
            ) in read_pcap_packets(file):

                decoder.total_packets += 1

                decoder.decode_ethernet(
                    raw_packet,

                    timestamp=timestamp,

                    # Number of bytes actually captured.
                    capture_length=capture_length,

                    # Original packet size on the wire.
                    wire_length=wire_length,
                )

                if (
                    packet_limit is not None
                    and decoder.total_packets
                    >= packet_limit
                ):

                    break

    except FileNotFoundError:

        print(
            f"[ERROR] PCAP file not found: "
            f"{filename}"
        )

        sys.exit(1)

    except (
        ValueError,
        dpkt.dpkt.Error
    ) as error:

        print(
            f"[ERROR] Could not decode PCAP: "
            f"{error}"
        )

        sys.exit(1)

    finally:

        decoder.print_statistics()

    return decoder


# ============================================================
# Phase 2 -> Phase 3 Handoff
# ============================================================

def print_packet_objects(decoder):
    """
    Optional inspection helper.

    The Packet objects are the contract for:

        Packet
          ↓
        Flow Manager
          ↓
        IP Reassembly
          ↓
        TCP Reassembly
          ↓
        Normalization
          ↓
        Detection

    It is intentionally NOT called by default.
    """

    print()
    print("=" * 80)
    print("PACKET OBJECTS (PHASE 3 HANDOFF)")
    print("=" * 80)

    for index, packet in enumerate(
        decoder.packets,
        start=1
    ):

        print(
            f"[{index}] {packet.summary()}"
        )

        print(
            f"     timestamp          : "
            f"{format_timestamp(packet.timestamp)}"
        )

        print(
            f"     capture_length     : "
            f"{packet.capture_length}"
        )

        print(
            f"     wire_length        : "
            f"{packet.wire_length}"
        )

        print(
            f"     flow_key           : "
            f"{packet.flow_key}"
        )

        print(
            f"     ip_fragment_key    : "
            f"{packet.ip_fragment_key}"
        )

        print(
            f"     fragment_offset    : "
            f"{packet.fragment_offset}"
        )

        print(
            f"     offset_bytes       : "
            f"{packet.fragment_offset_bytes}"
        )

        print(
            f"     more_fragments     : "
            f"{packet.more_fragments}"
        )

        print(
            f"     payload_length     : "
            f"{packet.payload_length()}"
        )


# ============================================================
# CLI
# ============================================================

def get_arguments():

    parser = argparse.ArgumentParser(
        description="Phase 2 PCAP packet decoder"
    )

    parser.add_argument(
        "pcap",
        help="PCAP file generated by phase2_capture.py"
    )

    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=None,
        help="Maximum number of packets to decode"
    )

    return parser.parse_args()


# ============================================================
# Main
# ============================================================

def main():

    args = get_arguments()

    print()
    print("=" * 80)
    print("              CUSTOM IDS - PHASE 2")
    print("                  PACKET DECODER")
    print("=" * 80)

    print()
    print(
        f"PCAP file : {args.pcap}"
    )

    if args.limit:

        print(
            f"Limit     : "
            f"{args.limit} packets"
        )

    else:

        print(
            "Limit     : all packets"
        )

    decoder = decode_pcap(
        filename=args.pcap,
        packet_limit=args.limit
    )

    # Uncomment when you want to inspect the
    # Phase 2 -> Phase 3 contract.
    #
    # print_packet_objects(decoder)


if __name__ == "__main__":
    main()
