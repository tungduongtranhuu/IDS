"""PCAP reading and layered packet decoding for Phase 2."""

import logging
import struct

import dpkt

from .packet import Packet
from .utils import (
    ascii_preview,
    format_tcp_flags,
    format_timestamp,
    hex_preview,
    ip_to_string,
    mac_to_string,
    protocol_name,
)


LOGGER = logging.getLogger(__name__)


def read_pcap_packets(file):
    """Yield timestamp, raw bytes, captured length, and wire length from classic PCAP."""
    global_header = file.read(24)
    if len(global_header) != 24:
        raise ValueError("Invalid or truncated PCAP global header")

    magic = global_header[:4]
    endian_by_magic = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    endian = endian_by_magic.get(magic)
    if endian is None:
        raise ValueError("Unsupported PCAP format or invalid PCAP magic number")

    nanosecond_precision = magic in (
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    )
    timestamp_divisor = 1_000_000_000 if nanosecond_precision else 1_000_000

    while True:
        packet_header = file.read(16)
        if not packet_header:
            return
        if len(packet_header) != 16:
            raise ValueError("Truncated PCAP packet header")

        ts_sec, ts_fraction, incl_len, orig_len = struct.unpack(
            endian + "IIII",
            packet_header,
        )
        raw_packet = file.read(incl_len)
        if len(raw_packet) != incl_len:
            raise ValueError("Truncated PCAP packet data")

        yield (
            ts_sec + ts_fraction / timestamp_divisor,
            raw_packet,
            incl_len,
            orig_len,
        )


class PacketDecoder:
    """Decode Ethernet/IPv4/transport layers and build Packet objects."""

    def __init__(self, output_mode="normal"):
        self.output_mode = output_mode
        self.total_packets = 0
        self.ipv4_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0
        self.fragmented_packets = 0
        self.other_packets = 0
        self.packets = []

    def _ethernet_fields(self, eth):
        if eth is None:
            return {"src_mac": "unknown", "dst_mac": "unknown", "ethertype": None}
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

        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
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
            "fragment_offset": fragment_offset,
            "fragment_offset_bytes": fragment_offset * 8,
            "more_fragments": bool(ip.off & dpkt.ip.IP_MF),
            "dont_fragment": bool(ip.off & dpkt.ip.IP_DF),
            "ip_options": bytes(getattr(ip, "opts", b"")),
            "ip_fragment_key": (src_ip, dst_ip, ip.p, ip.id),
            "src_port": src_port,
            "dst_port": dst_port,
        }

    def _transport_fields(self, tcp, udp, icmp):
        empty = {
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
        if tcp is not None:
            return {
                **empty,
                "tcp_seq": tcp.seq,
                "tcp_ack": tcp.ack,
                "tcp_flags": tcp.flags,
                "tcp_flags_text": format_tcp_flags(tcp.flags),
                "tcp_window": tcp.win,
                "tcp_header_length": tcp.off * 4,
                "tcp_checksum": tcp.sum,
                "tcp_urgent_pointer": tcp.urp,
                "tcp_options": bytes(getattr(tcp, "opts", b"")),
            }
        if udp is not None:
            return {
                **empty,
                "udp_length": udp.ulen,
                "udp_checksum": udp.sum,
            }
        if icmp is not None:
            identifier = None
            sequence = None
            icmp_data = getattr(icmp, "data", None)
            if isinstance(icmp_data, dpkt.icmp.ICMP.Echo):
                identifier = icmp_data.id
                sequence = icmp_data.seq
            return {
                **empty,
                "icmp_type": icmp.type,
                "icmp_code": icmp.code,
                "icmp_checksum": icmp.sum,
                "icmp_identifier": identifier,
                "icmp_sequence": sequence,
            }
        return empty

    def build_packet(self, **data):
        packet = Packet(
            timestamp=data["timestamp"],
            capture_length=data.get("capture_length"),
            wire_length=data.get("wire_length"),
            payload=data.get("payload", b""),
            flow_key=data.get("flow_key"),
            **self._ethernet_fields(data.get("eth")),
            **self._ipv4_fields(
                data.get("ip"),
                data["protocol"],
                data["src_ip"],
                data["dst_ip"],
                data.get("src_port"),
                data.get("dst_port"),
            ),
            **self._transport_fields(
                data.get("tcp"),
                data.get("udp"),
                data.get("icmp"),
            ),
        )
        self.packets.append(packet)
        self._log_packet(packet)
        return packet

    def _log_packet(self, packet):
        if self.output_mode == "verbose":
            LOGGER.info("[%d] %s", len(self.packets), packet.summary())
        elif self.output_mode == "debug":
            LOGGER.debug("Packet #%d", len(self.packets))
            LOGGER.debug("  timestamp: %s", format_timestamp(packet.timestamp))
            LOGGER.debug("  ethernet: %s -> %s, type=0x%04x", packet.src_mac, packet.dst_mac, packet.ethertype or 0)
            LOGGER.debug("  network: %s -> %s, protocol=%s, ttl=%s, id=%s", packet.src_ip, packet.dst_ip, packet.ip_protocol, packet.ip_ttl, packet.ip_id)
            LOGGER.debug("  transport: %s:%s -> %s:%s, flags=%s, seq=%s, ack=%s", packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, packet.tcp_flags_text, packet.tcp_seq, packet.tcp_ack)
            LOGGER.debug("  flow_key: %s", packet.flow_key)
            LOGGER.debug("  fragment_key: %s, offset=%s, more=%s", packet.ip_fragment_key, packet.fragment_offset_bytes, packet.more_fragments)
            LOGGER.debug("  payload length: %d", packet.payload_length())
            if packet.payload:
                LOGGER.debug("  payload bytes: %r", packet.payload)
                LOGGER.debug("  payload hex: %s", hex_preview(packet.payload))
                LOGGER.debug("  payload ascii: %s", ascii_preview(packet.payload))

    def decode_ethernet(self, raw_packet, timestamp=0.0, capture_length=None, wire_length=None):
        try:
            eth = dpkt.ethernet.Ethernet(raw_packet)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as error:
            LOGGER.warning("Invalid Ethernet frame: %s", error)
            return None

        if capture_length is None:
            capture_length = len(raw_packet)
        if not isinstance(eth.data, dpkt.ip.IP):
            self.other_packets += 1
            LOGGER.debug("Ignoring non-IPv4 Ethernet frame, ethertype=0x%04x", eth.type)
            return None

        self.ipv4_packets += 1
        return self.decode_ipv4(
            eth.data,
            timestamp,
            eth,
            capture_length=capture_length,
            wire_length=wire_length,
        )

    def decode_ipv4(self, ip, timestamp=0.0, eth=None, capture_length=None, wire_length=None):
        src_ip = ip_to_string(ip.src)
        dst_ip = ip_to_string(ip.dst)
        protocol = protocol_name(ip.p)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        if fragment_offset or more_fragments:
            self.fragmented_packets += 1

        if fragment_offset != 0:
            return self.build_packet(
                timestamp=timestamp,
                eth=eth,
                ip=ip,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                payload=bytes(ip.data),
                capture_length=capture_length,
                wire_length=wire_length,
            )

        transport = ip.data
        if isinstance(transport, dpkt.tcp.TCP):
            self.tcp_packets += 1
            return self.decode_tcp(src_ip, dst_ip, transport, timestamp, eth, ip, capture_length, wire_length)
        if isinstance(transport, dpkt.udp.UDP):
            self.udp_packets += 1
            return self.decode_udp(src_ip, dst_ip, transport, timestamp, eth, ip, capture_length, wire_length)
        if isinstance(transport, dpkt.icmp.ICMP):
            self.icmp_packets += 1
            return self.decode_icmp(src_ip, dst_ip, transport, timestamp, eth, ip, capture_length, wire_length)

        self.other_packets += 1
        return self.build_packet(
            timestamp=timestamp,
            eth=eth,
            ip=ip,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            payload=bytes(transport),
            capture_length=capture_length,
            wire_length=wire_length,
        )

    def decode_tcp(self, src_ip, dst_ip, tcp, timestamp=0.0, eth=None, ip=None, capture_length=None, wire_length=None):
        flow_key = (src_ip, dst_ip, tcp.sport, tcp.dport, "TCP")
        return self.build_packet(
            timestamp=timestamp,
            eth=eth,
            ip=ip,
            protocol="TCP",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=tcp.sport,
            dst_port=tcp.dport,
            tcp=tcp,
            payload=bytes(tcp.data),
            flow_key=flow_key,
            capture_length=capture_length,
            wire_length=wire_length,
        )

    def decode_udp(self, src_ip, dst_ip, udp, timestamp=0.0, eth=None, ip=None, capture_length=None, wire_length=None):
        flow_key = (src_ip, dst_ip, udp.sport, udp.dport, "UDP")
        return self.build_packet(
            timestamp=timestamp,
            eth=eth,
            ip=ip,
            protocol="UDP",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=udp.sport,
            dst_port=udp.dport,
            udp=udp,
            payload=bytes(udp.data),
            flow_key=flow_key,
            capture_length=capture_length,
            wire_length=wire_length,
        )

    def decode_icmp(self, src_ip, dst_ip, icmp, timestamp=0.0, eth=None, ip=None, capture_length=None, wire_length=None):
        flow_key = (src_ip, dst_ip, None, None, "ICMP")
        payload = bytes(icmp.data) if getattr(icmp, "data", None) else b""
        return self.build_packet(
            timestamp=timestamp,
            eth=eth,
            ip=ip,
            protocol="ICMP",
            src_ip=src_ip,
            dst_ip=dst_ip,
            icmp=icmp,
            payload=payload,
            flow_key=flow_key,
            capture_length=capture_length,
            wire_length=wire_length,
        )

    def print_statistics(self):
        LOGGER.info(
            "Decoded packets: total=%d ipv4=%d tcp=%d udp=%d icmp=%d fragments=%d other=%d objects=%d",
            self.total_packets,
            self.ipv4_packets,
            self.tcp_packets,
            self.udp_packets,
            self.icmp_packets,
            self.fragmented_packets,
            self.other_packets,
            len(self.packets),
        )


def decode_pcap(filename, packet_limit=None, output_mode="normal"):
    decoder = PacketDecoder(output_mode=output_mode)
    try:
        with open(filename, "rb") as file:
            for timestamp, raw_packet, capture_length, wire_length in read_pcap_packets(file):
                decoder.total_packets += 1
                decoder.decode_ethernet(
                    raw_packet,
                    timestamp=timestamp,
                    capture_length=capture_length,
                    wire_length=wire_length,
                )
                if packet_limit is not None and decoder.total_packets >= packet_limit:
                    break
    except FileNotFoundError:
        LOGGER.error("PCAP file not found: %s", filename)
        return decoder
    except (ValueError, dpkt.dpkt.Error) as error:
        LOGGER.exception("Could not decode PCAP: %s", error)
        return decoder
    decoder.print_statistics()
    return decoder


def print_packet_objects(decoder):
    """Compatibility helper for detailed Packet inspection."""
    for index, packet in enumerate(decoder.packets, start=1):
        LOGGER.debug(
            "[%d] %s timestamp=%s flow_key=%s fragment_key=%s offset=%s payload_length=%d",
            index,
            packet.summary(),
            format_timestamp(packet.timestamp),
            packet.flow_key,
            packet.ip_fragment_key,
            packet.fragment_offset,
            packet.payload_length(),
        )
