#!/usr/bin/env python3

"""
Phase 2 - Packet Decoder

Responsibilities:
    1. Read packets from a PCAP file.
    2. Decode Ethernet.
    3. Decode IPv4.
    4. Decode TCP / UDP / ICMP.
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

Run:
    python3 phase2_decode.py capture.pcap

Example:
    python3 phase2_decode.py capture.pcap --limit 20
"""

import argparse
import socket
import sys

import dpkt


# ============================================================
# Constants
# ============================================================

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

    # --------------------------------------------------------
    # Ethernet
    # --------------------------------------------------------

    def decode_ethernet(self, timestamp, raw_packet):

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

        self.decode_ipv4(ip)

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    def decode_ipv4(self, ip):

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
                ip.data
            )

        elif isinstance(ip.data, dpkt.udp.UDP):

            self.udp_packets += 1

            self.decode_udp(
                src_ip,
                dst_ip,
                ip.data
            )

        elif isinstance(ip.data, dpkt.icmp.ICMP):

            self.icmp_packets += 1

            self.decode_icmp(
                src_ip,
                dst_ip,
                ip.data
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

    def decode_tcp(self, src_ip, dst_ip, tcp):

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

    def decode_udp(self, src_ip, dst_ip, udp):

        payload = bytes(udp.data)

        flow_key = (
            src_ip,
            dst_ip,
            udp.sport,
            udp.dport,
            "UDP"
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

    def decode_icmp(self, src_ip, dst_ip, icmp):

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

                decoder.decode_ethernet(
                    timestamp,
                    raw_packet
                )

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

