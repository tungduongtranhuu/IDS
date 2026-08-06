#!/usr/bin/env python3

"""
Phase 2 - Packet Decoder

Responsibilities:
    1. Read packets from a PCAP file.
    2. Decode Ethernet.
    3. Decode IPv4.
    4. Decode TCP / UDP / ICMP.
       Non-IPv4 packets are still reported and ignored in Phase 2.
    5. Extract:
         - MAC addresses
         - IP addresses
         - protocol
         - ports
         - TCP sequence number
         - TCP acknowledgement number
         - TCP flags
         - IP fragmentation information
         - payload
         - 5-tuple
         - Packet abstraction for Phase 3 Flow Manager / Reassembly

Run:
    python3 phase2_decode.py capture.pcap

Example:
    python3 phase2_decode.py capture.pcap --limit 20
"""

import argparse
import socket
import sys
from dataclasses import dataclass, field
from typing import Optional

import dpkt


# ============================================================
# Constants
# ============================================================

# Chuyển TCP Flags từ dạng bit/hex sang tên dễ đọc
TCP_FLAGS = {
    dpkt.tcp.TH_FIN: "FIN", # Về mặt ý nghĩa thì dpkt.tcp.TH_FIN = 0x01
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
        return socket.inet_ntoa(ip) # chuyển đổi địa chỉ ipv4 từ dạng bytes sang string b'\x7f\x00\x00\x01' -> 127.0.0.1

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

    return ",".join(names) # names = ['SYN', 'ACK'] -> "SYN,ACK"


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
# Packet Object
# ============================================================

@dataclass
class Packet:
    """
    Normalized packet abstraction used by later IDS phases.

    Phase 2 only creates this object.
    Flow tracking, reassembly and detection are NOT implemented here.
    """

    timestamp: float

    # Ethernet
    src_mac: str
    dst_mac: str
    ethertype: int

    # IPv4
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_protocol: Optional[str] = None
    ip_protocol_number: Optional[int] = None
    ip_ttl: Optional[int] = None
    ip_id: Optional[int] = None
    ip_header_length: Optional[int] = None
    ip_total_length: Optional[int] = None
    fragment_offset: int = 0
    more_fragments: bool = False
    dont_fragment: bool = False

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

    # ICMP
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # Payload
    payload: bytes = field(default_factory=bytes)

    # Directional 5-tuple:
    # (src_ip, dst_ip, src_port, dst_port, protocol)
    flow_key: Optional[tuple] = None

    def payload_length(self) -> int:
        return len(self.payload)

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
        self.other_packets = 0
        # Phase 2 output for Phase 3 (Flow Manager / Reassembly).
        self.packets = []

    # --------------------------------------------------------
    # Packet Object factory
    # --------------------------------------------------------

    def _ethernet_fields(self, eth):
        if eth is None:
            return {
                "src_mac": "unknown",
                "dst_mac": "unknown",
                "ethertype": 0,
            }

        return {
            "src_mac": mac_to_string(eth.src),
            "dst_mac": mac_to_string(eth.dst),
            "ethertype": eth.type,
        }

    def _ipv4_fields(self, ip, protocol, src_ip, dst_ip, src_port, dst_port):
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
                "fragment_offset": 0,
                "more_fragments": False,
                "dont_fragment": False,
                "src_port": src_port,
                "dst_port": dst_port,
            }

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ip_protocol": protocol,
            "ip_protocol_number": ip.p,
            "ip_ttl": ip.ttl,
            "ip_id": ip.id,
            "ip_header_length": ip.hl * 4,
            "ip_total_length": ip.len,
            "fragment_offset": ip.off & dpkt.ip.IP_OFFMASK,
            "more_fragments": bool(ip.off & dpkt.ip.IP_MF),
            "dont_fragment": bool(ip.off & dpkt.ip.IP_DF),
            "src_port": src_port,
            "dst_port": dst_port,
        }

    def _transport_fields(self, tcp, icmp):
        if tcp is not None:
            return {
                "tcp_seq": tcp.seq,
                "tcp_ack": tcp.ack,
                "tcp_flags": tcp.flags,
                "tcp_flags_text": format_tcp_flags(tcp.flags),
                "tcp_window": tcp.win,
                "tcp_header_length": tcp.off * 4,
                "icmp_type": None,
                "icmp_code": None,
            }

        if icmp is not None:
            return {
                "tcp_seq": None,
                "tcp_ack": None,
                "tcp_flags": None,
                "tcp_flags_text": None,
                "tcp_window": None,
                "tcp_header_length": None,
                "icmp_type": icmp.type,
                "icmp_code": icmp.code,
            }

        return {
            "tcp_seq": None,
            "tcp_ack": None,
            "tcp_flags": None,
            "tcp_flags_text": None,
            "tcp_window": None,
            "tcp_header_length": None,
            "icmp_type": None,
            "icmp_code": None,
        }

    def build_packet(self, timestamp, eth, ip, protocol,
                     src_ip, dst_ip, src_port=None, dst_port=None,
                     tcp=None, icmp=None, payload=b"", flow_key=None):
        """Build the normalized Packet object consumed by Phase 3."""
        packet = Packet(
            timestamp=timestamp,
            payload=payload,
            flow_key=flow_key,
            **self._ethernet_fields(eth),
            **self._ipv4_fields(ip, protocol, src_ip, dst_ip, src_port, dst_port),
            **self._transport_fields(tcp, icmp),
        )
        self.packets.append(packet)

    # --------------------------------------------------------
    # Ethernet
    # --------------------------------------------------------

    def decode_ethernet(self, raw_packet, timestamp=0.0):

        try:
            eth = dpkt.ethernet.Ethernet(raw_packet)

        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            print("[!] Invalid Ethernet frame.")
            return

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

        # ----------------------------------------------------
        # Only process IPv4 for Phase 2
        # ----------------------------------------------------

        if not isinstance(eth.data, dpkt.ip.IP):

            self.other_packets += 1

            print()
            print("  Non-IPv4 packet.")
            print("  Decoder stops at Ethernet layer.")

            return

        self.ipv4_packets += 1

        ip = eth.data

        self.decode_ipv4(ip, timestamp, eth)

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    def decode_ipv4(self, ip, timestamp=0.0, eth=None):

        src_ip = ip_to_string(ip.src)
        dst_ip = ip_to_string(ip.dst)

        protocol = protocol_name(ip.p)

        # ----------------------------------------------------
        # IP fragmentation information
        # ----------------------------------------------------

        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        more_fragments = bool(
            ip.off & dpkt.ip.IP_MF
        )

        dont_fragment = bool(
            ip.off & dpkt.ip.IP_DF
        )

        print()
        print("IPv4")
        print("-" * 80)

        print(
            f"  Source IP       : {src_ip}"
        )

        print(
            f"  Destination IP  : {dst_ip}"
        )

        print(
            f"  Protocol        : {protocol}"
        )

        print(
            f"  TTL             : {ip.ttl}"
        )

        print(
            f"  Identification  : {ip.id}"
        )

        print(
            f"  Header Length   : {ip.hl * 4} bytes"
        )

        print(
            f"  Total Length    : {ip.len} bytes"
        )

        print(
            f"  Fragment Offset : {fragment_offset}"
        )

        print(
            f"  More Fragments  : {more_fragments}"
        )

        print(
            f"  Don't Fragment  : {dont_fragment}"
        )

        # ----------------------------------------------------
        # IMPORTANT:
        #
        # If this packet is fragmented, TCP/UDP header may
        # not exist in this fragment.
        #
        # For Phase 2 we simply report it.
        #
        # Actual reassembly will be implemented in Phase 3.
        # ----------------------------------------------------

        if fragment_offset != 0:

            print()
            print(
                "  [!] Non-first IP fragment."
            )

            print(
                "  [!] Transport header may not be available."
            )

            print(
                "  [!] Phase 3 will implement IP reassembly."
            )

            return

        # ----------------------------------------------------
        # Transport protocol
        # ----------------------------------------------------

        if isinstance(ip.data, dpkt.tcp.TCP):

            self.tcp_packets += 1

            self.decode_tcp(
                src_ip,
                dst_ip,
                ip.data,
                timestamp=timestamp,
                eth=eth,
                ip=ip
            )

        elif isinstance(ip.data, dpkt.udp.UDP):

            self.udp_packets += 1

            self.decode_udp(
                src_ip,
                dst_ip,
                ip.data,
                timestamp=timestamp,
                eth=eth,
                ip=ip
            )

        elif isinstance(ip.data, dpkt.icmp.ICMP):

            self.icmp_packets += 1

            self.decode_icmp(
                src_ip,
                dst_ip,
                ip.data,
                timestamp=timestamp,
                eth=eth,
                ip=ip
            )

        else:

            self.other_packets += 1

            print()
            print(
                f"  Transport protocol "
                f"not decoded: {protocol}"
            )

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    def decode_tcp(self, src_ip, dst_ip, tcp, timestamp=0.0, eth=None, ip=None):

        payload = bytes(tcp.data)

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
        )

        print()
        print("TCP")
        print("-" * 80)

        print(
            f"  Source Port      : {tcp.sport}"
        )

        print(
            f"  Destination Port : {tcp.dport}"
        )

        print(
            f"  Sequence Number  : {tcp.seq}"
        )

        print(
            f"  Acknowledgement  : {tcp.ack}"
        )

        print(
            f"  Flags            : {flags}"
        )

        print(
            f"  Window           : {tcp.win}"
        )

        print(
            f"  TCP Header Len   : {tcp.off * 4} bytes"
        )

        print(
            f"  Payload Length   : {len(payload)} bytes"
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
            print("  No TCP payload.")

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    def decode_udp(self, src_ip, dst_ip, udp, timestamp=0.0, eth=None, ip=None):

        payload = bytes(udp.data)

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
            payload=payload,
            flow_key=flow_key,
        )

        print()
        print("UDP")
        print("-" * 80)

        print(
            f"  Source Port      : {udp.sport}"
        )

        print(
            f"  Destination Port : {udp.dport}"
        )

        print(
            f"  UDP Length       : {udp.ulen}"
        )

        print(
            f"  Payload Length   : {len(payload)}"
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

    # --------------------------------------------------------
    # ICMP
    # --------------------------------------------------------

    def decode_icmp(self, src_ip, dst_ip, icmp, timestamp=0.0, eth=None, ip=None):

        payload = bytes(icmp.data) if getattr(icmp, "data", None) else b""

        self.build_packet(
            timestamp=timestamp,
            eth=eth,
            ip=ip,
            protocol="ICMP",
            src_ip=src_ip,
            dst_ip=dst_ip,
            icmp=icmp,
            payload=payload,
            flow_key=(src_ip, dst_ip, None, None, "ICMP"),
        )

        print()
        print("ICMP")
        print("-" * 80)

        print(
            f"  Source IP      : {src_ip}"
        )

        print(
            f"  Destination IP : {dst_ip}"
        )

        print(
            f"  Type           : {icmp.type}"
        )

        print(
            f"  Code           : {icmp.code}"
        )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    def print_statistics(self):

        print()
        print()
        print("=" * 80)
        print("CAPTURE / DECODING STATISTICS")
        print("=" * 80)

        print(
            f"Total packets : {self.total_packets}"
        )

        print(
            f"IPv4 packets  : {self.ipv4_packets}"
        )

        print(
            f"TCP packets   : {self.tcp_packets}"
        )

        print(
            f"UDP packets   : {self.udp_packets}"
        )

        print(
            f"ICMP packets  : {self.icmp_packets}"
        )

        print(
            f"Other packets : {self.other_packets}"
        )

        print(
            f"Packet objects: {len(self.packets)}"
        )

        print("=" * 80)


# ============================================================
# PCAP Processing
# ============================================================

def decode_pcap(filename, packet_limit=None):

    decoder = PacketDecoder()

    try:

        with open(filename, "rb") as file:

            pcap = dpkt.pcap.Reader(file)

            for timestamp, raw_packet in pcap:

                decoder.total_packets += 1

                decoder.decode_ethernet(raw_packet, timestamp=timestamp)

                if (
                    packet_limit is not None
                    and decoder.total_packets >= packet_limit
                ):
                    break

    except FileNotFoundError:

        print(
            f"[ERROR] PCAP file not found: {filename}"
        )

        sys.exit(1)

    except (ValueError, dpkt.dpkt.Error) as error:

        print(
            f"[ERROR] Could not decode PCAP: {error}"
        )

        sys.exit(1)

    finally:

        decoder.print_statistics()



# ============================================================
# Phase 2 -> Phase 3 Handoff
# ============================================================

def print_packet_objects(decoder):
    """
    Optional inspection helper.

    The Packet objects are the contract for:
        Packet -> Flow Manager -> Reassembly -> Detection

    It is intentionally NOT called by default.
    """
    print()
    print("=" * 80)
    print("PACKET OBJECTS (PHASE 3 HANDOFF)")
    print("=" * 80)

    for index, packet in enumerate(decoder.packets, start=1):
        print(f"[{index}] {packet.summary()}")
        print(f"     timestamp       : {packet.timestamp}")
        print(f"     flow_key        : {packet.flow_key}")
        print(f"     fragment_offset : {packet.fragment_offset}")
        print(f"     more_fragments  : {packet.more_fragments}")
        print(f"     payload_length  : {packet.payload_length()}")


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
    print(f"PCAP file : {args.pcap}")

    if args.limit:
        print(f"Limit     : {args.limit} packets")
    else:
        print("Limit     : all packets")

    decode_pcap(
        filename=args.pcap,
        packet_limit=args.limit
    )


if __name__ == "__main__":
    main()
