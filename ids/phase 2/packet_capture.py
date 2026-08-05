#!/usr/bin/env python3

"""
Phase 2 - Packet Capture

Responsibilities:
    1. Open a Linux AF_PACKET raw socket.
    2. Capture Ethernet frames from a network interface.
    3. Store captured frames in a PCAP file.
    4. Print basic capture statistics.

Run:
    sudo python3 phase2_capture.py

Example:
    sudo python3 phase2_capture.py --interface enp0s3

Stop:
    Ctrl+C
"""

import argparse 
# dùng để đọc command-line arguments (--interface trong python3 phase2_capture.py --interface enp0s3 được xử lý bởi thư viện này)
import os
import socket
import struct
# Nó cho phép bạn biến dữ liệu Python thành binary bytes theo format cụ thể.
import sys
import time
from datetime import datetime


# ============================================================
# Configuration
# ============================================================

DEFAULT_INTERFACE = "enp0s3"
DEFAULT_OUTPUT = "capture.pcap"
DEFAULT_SNAPLEN = 65535 # số bytes lấy được từ 1 packet Ethernet

# Linux Ethernet protocol: nhận tất cả các Ethernet protocols IPv4, IPv6, 802.1Q
# ETH_P_ALL = 0x0003
ETH_P_ALL = 0x0003


# ============================================================
# PCAP Writer
# ============================================================

class PcapWriter:
    """
    Minimal PCAP writer.

    We manually write the PCAP global header and packet records
    so that the capture file can later be opened by Wireshark,
    tcpdump, or parsed by dpkt.

    Format .pcap

    # PCAP Global Header
    # Packet Header
    # Packet Data
    #
    # Packet Header
    # Packet Data
    #
    # Packet Header
    # Packet Data
    """

    def __init__(self, filename):
        self.filename = filename

        self.file = open(filename, "wb")

        # PCAP Global Header là header của file .pcap định dạng format chung cho toàn bộ các gói tin được lưu trong file .pcap
        #
        # magic_number  : 0xa1b2c3d4
        # version_major : 2
        # version_minor : 4
        # thiszone      : 0
        # sigfigs       : 0
        # snaplen       : 65535
        # network       : 1 = Ethernet
        #

        global_header = struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,
            2,
            4,
            0,
            0,
            DEFAULT_SNAPLEN,
            1
        )
        # Hãy tạo cho tôi một PCAP file (PCAP magic number 0xA1B2C3D4) 
        # theo format PCAP 2.4 (version_major : 2, version_minor : 4), 
        # sử dụng little-endian (<),
        # không có timezone (thiszone = 0)
        # timestamp không sử dụng độ chính xác đặc biệt (sigfigs = 0), 
        # mỗi packet có thể được capture tối đa DEFAULT_SNAPLEN bytes (snaplen), 
        # và packet data là Ethernet (network = 1)."

        self.file.write(global_header)
        self.file.flush()

    def write_packet(self, packet_data):
        """
        Write one Ethernet frame into the PCAP file.
        """

        timestamp = time.time()

        seconds = int(timestamp)
        microseconds = int((timestamp - seconds) * 1_000_000)

        packet_length = len(packet_data)

        packet_header = struct.pack(
            "<IIII",
            seconds,
            microseconds,
            packet_length,
            packet_length
        )

        self.file.write(packet_header)
        self.file.write(packet_data)
        self.file.flush()

    def close(self):
        if self.file:
            self.file.close()


# ============================================================
# Utility Functions
# ============================================================

def get_arguments():
    """
    Hàm xử lý command line
    Ví dụ: sudo python3 packet_capture.py -i enp0s4 -o file.pcap
    2 parameters -i và -o cho phép chọn interface input và file pcap output
    Nếu chỉ viết sudo python3 packet_capture.py thì mặc định enp0s3 và capture.pcap
    """
    parser = argparse.ArgumentParser(
        description="Phase 2 raw Ethernet packet capture"
    )

    parser.add_argument(
        "-i",
        "--interface",
        default=DEFAULT_INTERFACE,
        help=f"Network interface (default: {DEFAULT_INTERFACE})"
    )

    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Output PCAP file (default: {DEFAULT_OUTPUT})"
    )

    return parser.parse_args()


def check_root():
    """
    Raw packet capture normally requires root privileges.
    In Linux root's UID is always 0
    """

    if os.geteuid() != 0:
        print("[ERROR] This program must be run as root.")
        print()
        print("Run:")
        print("    sudo python3 phase2_capture.py")
        sys.exit(1)


def check_interface(interface):
    """
    Verify that the interface exists.
    """

    try:
        socket.if_nametoindex(interface)
    except OSError:
        print(f"[ERROR] Interface '{interface}' does not exist.")
        print()
        print("Available interfaces:")
        print_available_interfaces()
        sys.exit(1)


def print_available_interfaces():
    try:
        interfaces = socket.if_nameindex()

        for _, name in interfaces:
            print(f"    - {name}")

    except Exception:
        print("    Unable to list interfaces.")


def print_banner(interface, output):
    print()
    print("=" * 70)
    print("                CUSTOM IDS - PHASE 2")
    print("                    PACKET CAPTURE")
    print("=" * 70)
    print()
    print(f"Interface : {interface}")
    print(f"Output    : {output}")
    print(f"Protocol  : ETH_P_ALL (0x{ETH_P_ALL:04x})")
    print()
    print("Waiting for packets...")
    print("Press Ctrl+C to stop.")
    print()
    print("=" * 70)


# ============================================================
# Packet Capture
# ============================================================

def capture_packets(interface, output):
    """
    Capture raw Ethernet frames using Linux AF_PACKET.
    """

    check_root()
    check_interface(interface)

    print_banner(interface, output)

    packet_count = 0
    total_bytes = 0

    pcap_writer = None
    raw_socket = None

    try:

        # Create Linux raw packet socket
        #
        # AF_PACKET:
        #   Access packets at Ethernet/link layer.
        #
        # SOCK_RAW:
        #   Receive the complete Ethernet frame (Dest MAC, Source MAC, EtherType, Payload).
        #
        # htons(ETH_P_ALL): //htons: host to network short
        #   Receive all Ethernet protocols.
        #
        raw_socket = socket.socket(
            socket.AF_PACKET, # truy cập trức tiếp tầng Ethernet
            socket.SOCK_RAW, # loại socket, nhận nguyên toàn bộ khung dữ liệu
            socket.htons(ETH_P_ALL) # bắt mọi gói tin đi qua card mạng ở mọi giao thức
        )

        # Bind socket to selected interface

        raw_socket.bind((interface, 0))

        # Create PCAP writer

        pcap_writer = PcapWriter(output)

        print(f"[+] Raw socket started on {interface}")
        print(f"[+] Writing packets to {output}")
        print()

        while True:

            # Receive raw Ethernet frame
            packet_data, address = raw_socket.recvfrom(DEFAULT_SNAPLEN)
            # addr -> tuple (interface_name, protocol, ptype, hatype, pkttype, halen, addr_bytes)
            if not packet_data:
                continue

            # Statistics
            packet_count += 1
            total_bytes += len(packet_data)

            # Save packet
            pcap_writer.write_packet(packet_data)

            # Display capture information
            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            protocol = address[2]

            print(
                f"[{timestamp}] "
                f"packet={packet_count:<8} "
                f"size={len(packet_data):<6} bytes "
                f"protocol=0x{protocol:04x}"
            )

    except KeyboardInterrupt:

        print()
        print()
        print("=" * 70)
        print("Capture stopped.")
        print("=" * 70)
        print()
        print(f"Packets captured : {packet_count}")
        print(f"Bytes captured   : {total_bytes}")
        print(f"PCAP file        : {output}")
        print()

    except PermissionError:

        print()
        print("[ERROR] Permission denied.")
        print("Run the program with sudo.")

    except OSError as error:

        print()
        print(f"[ERROR] Socket error: {error}")

    finally:

        if raw_socket is not None:
            raw_socket.close()

        if pcap_writer is not None:
            pcap_writer.close()

        print("[+] Resources released.")


# ============================================================
# Main
# ============================================================

def main():
    args = get_arguments()

    capture_packets(
        interface=args.interface,
        output=args.output
    )


if __name__ == "__main__":
    main()

### Thêm src và dst ở mỗi gói tin