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

Run:
    python3 phase2_decode.py capture.pcap

Example:
    python3 phase2_decode.py capture.pcap --limit 20
"""

import argparse
import socket
import sys
from dataclasses import dataclass, field
from typing import Optional, Tuple

import dpkt


# Constants

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


# Utility Functions

def mac_to_string(mac):
    """
    Convert binary MAC address to readable string.
    """

    if not mac:
        return "unknown"

    # chuyển từ dạng bytes sang dạng hex string, ví dụ: b'\x01\x02' -> "01:02"
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

    # chuyển từ dạng bytes sang dạng hex string, ví dụ: b'\x01\x02' -> "01 02"
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


# Protocol Name

def protocol_name(protocol):

    if protocol == dpkt.ip.IP_PROTO_TCP:
        return "TCP"

    if protocol == dpkt.ip.IP_PROTO_UDP:
        return "UDP"

    if protocol == dpkt.ip.IP_PROTO_ICMP:
        return "ICMP"

    return f"OTHER({protocol})"


# Packet Object

@dataclass
class Packet:
    """
    Normalized packet abstraction used by later IDS phases.

    Phase 2 only creates this object.

    Flow tracking, reassembly, normalization and detection
    are NOT implemented here.
    """

    # Capture metadata

    timestamp: float

    capture_length: Optional[int] = None
    wire_length: Optional[int] = None

    # Ethernet

    src_mac: str = "unknown"
    dst_mac: str = "unknown"
    ethertype: Optional[int] = None

    # IPv4

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    ip_protocol: Optional[str] = None
    ip_protocol_number: Optional[int] = None

    ip_ttl: Optional[int] = None
    ip_id: Optional[int] = None

    ip_header_length: Optional[int] = None
    ip_total_length: Optional[int] = None

    ip_checksum: Optional[int] = None

    # Raw fragment offset value from IPv4 header.
    # Unit = 8-byte blocks.
    fragment_offset: int = 0

    # Same offset converted to bytes.
    fragment_offset_bytes: int = 0

    more_fragments: bool = False
    dont_fragment: bool = False

    # IPv4 options preserved for future analysis.
    ip_options: bytes = field(default_factory=bytes)

    # Key required by IP Fragment Reassembly.
    #
    # (src_ip, dst_ip, protocol_number, ip_id)
    ip_fragment_key: Optional[tuple] = None

    # Transport

    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # TCP

    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None

    tcp_flags: Optional[int] = None
    tcp_flags_text: Optional[str] = None

    tcp_window: Optional[int] = None
    tcp_header_length: Optional[int] = None

    tcp_checksum: Optional[int] = None
    tcp_urgent_pointer: Optional[int] = None

    tcp_options: bytes = field(default_factory=bytes)

    # UDP

    udp_length: Optional[int] = None
    udp_checksum: Optional[int] = None

    # ICMP

    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    icmp_checksum: Optional[int] = None

    icmp_identifier: Optional[int] = None
    icmp_sequence: Optional[int] = None

    # Payload

    # Normalization belongs to a later phase.
    payload: bytes = field(default_factory=bytes)

    # Flow

    # Directional 5-tuple:
    #
    # (src_ip, dst_ip, src_port, dst_port, protocol)
    flow_key: Optional[tuple] = None

    # Helper methods
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


# Packet Decoder

class PacketDecoder:

    def __init__(self):

        self.total_packets = 0

        self.ipv4_packets = 0

        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0

        self.fragmented_packets = 0

        self.other_packets = 0

        # Phase 2 output for Phase 3
        # Flow Manager / Reassembly.
        self.packets = []

    # Packet Object factory

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
            # stored in units of 8 bytes.
            "fragment_offset": fragment_offset,

            # Converted to bytes for reassembly.
            "fragment_offset_bytes": fragment_offset * 8,

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

    def _transport_fields(self, tcp, udp, icmp):

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

                "tcp_header_length": tcp.off * 4,

                "tcp_checksum": tcp.sum,

                "tcp_urgent_pointer": tcp.urp,

                "tcp_options": bytes(
                    getattr(tcp, "opts", b"")
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

            # ICMP Echo Request / Echo Reply:
            #
            # type
            # code
            # checksum
            # id
            # sequence
            #
            # dpkt exposes these fields through the ICMP
            # Echo structure for Echo messages.

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
        """

        packet = Packet(

            timestamp=timestamp,

            capture_length=capture_length,
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

    # Ethernet

    def decode_ethernet(
        self,
        raw_packet,
        timestamp=0.0,
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

        capture_length = len(raw_packet)

        print()
        print("=" * 80)

        print(
            f"Packet #{self.total_packets}"
        )

        print("=" * 80)

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

    # IPv4

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

            # The payload of a non-first fragment is the
            # fragment data itself.
            #
            # Phase 3 will combine these fragments using:
            #
            # src_ip
            # dst_ip
            # protocol
            # ip_id
            # fragment_offset_bytes
            # more_fragments

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

            # Preserve unknown IPv4 payload as a Packet object.
            #
            # This is important because Phase 2 should not
            # silently destroy data that may be useful later.

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

    # TCP

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

        # ----------------------------------------------------
        # 5-tuple
        # ----------------------------------------------------

        print()
        print("5-TUPLE")
        print("-" * 80)

        print(
            f"  {flow_key}"
        )

        # ----------------------------------------------------
        # Payload
        # ----------------------------------------------------

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

    # UDP

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

    # ICMP

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

        payload = bytes(
            icmp.data
        ) if getattr(
            icmp,
            "data",
            None
        ) else b""

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

    # Statistics

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


# PCAP Processing

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

            pcap = dpkt.pcap.Reader(
                file
            )

            for timestamp, raw_packet in pcap:

                decoder.total_packets += 1

                # PCAP gives us the captured packet bytes.
                #
                # For normal non-truncated captures,
                # capture length == wire length.
                #
                # If the PCAP has a different captured/original
                # length representation, this can be extended
                # later depending on the capture format.

                capture_length = len(
                    raw_packet
                )

                decoder.decode_ethernet(
                    raw_packet,
                    timestamp=timestamp,
                    wire_length=capture_length,
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


# Phase 2 -> Phase 3 Handoff

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
            f"{packet.timestamp}"
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


# CLI

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


# Main

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
