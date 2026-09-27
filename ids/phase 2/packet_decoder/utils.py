"""Formatting and protocol helpers for Phase 2."""

import logging
import socket
from datetime import datetime, timezone

import dpkt


LOGGER = logging.getLogger(__name__)

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


def configure_logging(mode):
    """Configure terminal output for quiet, normal, verbose, or debug mode."""
    level = {
        "quiet": logging.ERROR,
        "normal": logging.INFO,
        "verbose": logging.INFO,
        "debug": logging.DEBUG,
    }[mode]
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def mac_to_string(mac):
    if not mac:
        return "unknown"
    return ":".join(f"{byte:02x}" for byte in mac)


def ip_to_string(ip):
    try:
        return socket.inet_ntoa(ip)
    except (OSError, TypeError):
        return "unknown"


def format_tcp_flags(flags):
    names = [name for value, name in TCP_FLAGS.items() if flags & value]
    return ",".join(names) if names else "NONE"


def hex_preview(data, length=64):
    preview = data[:length]
    result = " ".join(f"{byte:02x}" for byte in preview)
    return result + (" ..." if len(data) > length else "")


def ascii_preview(data, length=128):
    preview = data[:length]
    result = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in preview)
    return result + (" ..." if len(data) > length else "")


def format_timestamp(timestamp):
    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    ).strftime("%Y-%m-%d %H:%M:%S.%f")


def protocol_name(protocol):
    names = {
        dpkt.ip.IP_PROTO_TCP: "TCP",
        dpkt.ip.IP_PROTO_UDP: "UDP",
        dpkt.ip.IP_PROTO_ICMP: "ICMP",
    }
    return names.get(protocol, f"OTHER({protocol})")
