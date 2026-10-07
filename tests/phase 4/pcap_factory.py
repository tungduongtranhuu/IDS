"""Build synthetic Ethernet/IPv4/TCP/UDP frames and PCAP files for Phase 4 tests.

Every evasion scenario is generated here, byte by byte, so the tests do not
depend on captured attack traffic.
"""

import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path


CLIENT_IP = "192.168.10.20"
SERVER_IP = "192.168.10.30"
CLIENT_MAC = bytes.fromhex("020000000014")
SERVER_MAC = bytes.fromhex("02000000001e")

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
IP_MF = 0x2000


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ethernet(payload: bytes, src_mac=CLIENT_MAC, dst_mac=SERVER_MAC, vlan=None) -> bytes:
    header = dst_mac + src_mac
    if vlan is not None:
        header += struct.pack("!HH", 0x8100, vlan)
    return header + struct.pack("!H", 0x0800) + payload


def ipv4(src: str, dst: str, protocol: int, payload: bytes, ip_id=1, flags_offset=0, ttl=64) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        ip_id,
        flags_offset,
        ttl,
        protocol,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp_segment(src, dst, sport, dport, seq, ack, flags, payload=b"", window=64240) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH", sport, dport, seq % (1 << 32), ack % (1 << 32), 5 << 4, flags, window, 0, 0
    )
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    value = checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", value) + header[18:] + payload


def udp_datagram(src, dst, sport, dport, payload: bytes) -> bytes:
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, len(header) + len(payload))
    value = checksum(pseudo + header + payload) or 0xFFFF
    return header[:6] + struct.pack("!H", value) + payload


def fragment_frames(src, dst, protocol, transport: bytes, ip_id, pieces, vlan=None) -> list[bytes]:
    """Cut a transport segment into IP fragments.

    pieces: list of (offset_bytes, length) or (offset_bytes, data, more_fragments)
    for hand-made (overlapping / conflicting) fragments.
    """
    frames = []
    for piece in pieces:
        if len(piece) == 2:
            offset, length = piece
            data = transport[offset:offset + length]
            more = offset + length < len(transport)
        else:
            offset, data, more = piece
        flags_offset = (offset // 8) | (IP_MF if more else 0)
        frames.append(ethernet(ipv4(src, dst, protocol, data, ip_id, flags_offset), vlan=vlan))
    return frames


def write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as file:
        file.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in frames:
            seconds = int(timestamp)
            micros = int(round((timestamp - seconds) * 1_000_000))
            file.write(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
            file.write(frame)
    return path


@dataclass
class TcpConversation:
    """Generate frames of one TCP connection with correct sequence numbers."""

    client_port: int = 40000
    server_port: int = 80
    client_isn: int = 1000
    server_isn: int = 5000
    client_ip: str = CLIENT_IP
    server_ip: str = SERVER_IP
    start: float = 1_700_000_000.0
    step: float = 0.01
    frames: list[tuple[float, bytes]] = field(default_factory=list)
    client_sent: int = 0
    server_sent: int = 0
    ip_id: int = 100

    def _time(self) -> float:
        return self.start + self.step * len(self.frames)

    def _frame(self, from_client: bool, seq, ack, flags, payload=b"") -> bytes:
        self.ip_id += 1
        if from_client:
            segment = tcp_segment(self.client_ip, self.server_ip, self.client_port, self.server_port, seq, ack, flags, payload)
            return ethernet(ipv4(self.client_ip, self.server_ip, 6, segment, self.ip_id))
        segment = tcp_segment(self.server_ip, self.client_ip, self.server_port, self.client_port, seq, ack, flags, payload)
        return ethernet(ipv4(self.server_ip, self.client_ip, 6, segment, self.ip_id), SERVER_MAC, CLIENT_MAC)

    def add(self, frame: bytes) -> None:
        self.frames.append((self._time(), frame))

    def handshake(self) -> "TcpConversation":
        self.add(self._frame(True, self.client_isn, 0, TCP_SYN))
        self.add(self._frame(False, self.server_isn, self.client_isn + 1, TCP_SYN | TCP_ACK))
        self.add(self._frame(True, self.client_isn + 1, self.server_isn + 1, TCP_ACK))
        return self

    def client_seq(self, offset: int) -> int:
        return self.client_isn + 1 + offset

    def server_seq(self, offset: int) -> int:
        return self.server_isn + 1 + offset

    def client_segment(self, offset: int, payload: bytes, flags=TCP_PSH | TCP_ACK) -> bytes:
        """Client data frame placed at stream offset (offset 0 = first data byte)."""
        return self._frame(True, self.client_seq(offset), self.server_seq(self.server_sent), flags, payload)

    def server_segment(self, offset: int, payload: bytes, flags=TCP_PSH | TCP_ACK) -> bytes:
        return self._frame(False, self.server_seq(offset), self.client_seq(self.client_sent), flags, payload)

    def client_transport(self, offset: int, payload: bytes, flags=TCP_PSH | TCP_ACK) -> bytes:
        """Raw TCP segment bytes (no IP/Ethernet), used to build IP fragments."""
        return tcp_segment(
            self.client_ip, self.server_ip, self.client_port, self.server_port,
            self.client_seq(offset), self.server_seq(self.server_sent), flags, payload,
        )

    def send_client(self, payload: bytes, pieces=None) -> None:
        """Send client data in order, optionally split into pieces of given sizes."""
        sizes = pieces or [len(payload)]
        position = 0
        for size in sizes:
            self.add(self.client_segment(self.client_sent + position, payload[position:position + size]))
            position += size
        self.client_sent += len(payload)

    def send_server(self, payload: bytes) -> None:
        self.add(self.server_segment(self.server_sent, payload))
        self.server_sent += len(payload)

    def close(self) -> "TcpConversation":
        self.add(self._frame(True, self.client_seq(self.client_sent), self.server_seq(self.server_sent), TCP_FIN | TCP_ACK))
        self.add(self._frame(False, self.server_seq(self.server_sent), self.client_seq(self.client_sent + 1), TCP_FIN | TCP_ACK))
        self.add(self._frame(True, self.client_seq(self.client_sent + 1), self.server_seq(self.server_sent + 1), TCP_ACK))
        return self


HTTP_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


def scenario_tcp_out_of_order_sqli() -> list[tuple[float, bytes]]:
    """SQL injection split into 3 TCP segments sent in the order 1, 3, 2."""
    conversation = TcpConversation().handshake()
    request = b"GET /search.php?q=1%27+UNION+SELECT+password+FROM+users-- HTTP/1.1\r\nHost: victim\r\n\r\n"
    first, second = request[:25], request[25:40]
    third = request[40:]
    conversation.add(conversation.client_segment(0, first))
    conversation.add(conversation.client_segment(len(first) + len(second), third))
    conversation.add(conversation.client_segment(len(first), second))
    conversation.client_sent = len(request)
    conversation.send_server(HTTP_RESPONSE)
    return conversation.close().frames


def scenario_tcp_overlap_conflict() -> list[tuple[float, bytes]]:
    """Two different payloads for the same sequence range (classic IDS evasion).

    Bytes 20-35 are sent twice while bytes 0-20 are still missing: first a
    harmless decoy, then the real "UNION+SELECT+us". Both copies wait in the
    out-of-order buffer, so the overlap policy decides which one is kept
    ("first" keeps the decoy, "last" keeps the attack). Either way
    TCP_OVERLAP_CONFLICT must be raised.
    """
    conversation = TcpConversation(client_port=40001).handshake()
    request = b"GET /index.php?id=1+UNION+SELECT+user,pass+FROM+users HTTP/1.1\r\nHost: victim\r\n\r\n"
    decoy = b"aaaaaaaaaaaaaaa"
    conversation.add(conversation.client_segment(20, decoy))
    conversation.add(conversation.client_segment(20, request[20:35]))
    conversation.add(conversation.client_segment(0, request[:20]))
    conversation.add(conversation.client_segment(35, request[35:]))
    conversation.client_sent = len(request)
    conversation.send_server(HTTP_RESPONSE)
    return conversation.close().frames


def scenario_tcp_retransmission() -> list[tuple[float, bytes]]:
    """Benign retransmissions: identical bytes sent twice (no conflict)."""
    conversation = TcpConversation(client_port=40002).handshake()
    request = b"GET /index.html HTTP/1.1\r\nHost: server\r\n\r\n"
    conversation.add(conversation.client_segment(0, request[:20]))
    conversation.add(conversation.client_segment(0, request[:20]))
    conversation.add(conversation.client_segment(10, request[10:]))
    conversation.client_sent = len(request)
    conversation.send_server(HTTP_RESPONSE)
    return conversation.close().frames


def scenario_tcp_seq_wraparound() -> list[tuple[float, bytes]]:
    """Client ISN close to 2^32: the sequence number wraps inside the request."""
    conversation = TcpConversation(client_port=40003, client_isn=(1 << 32) - 10).handshake()
    conversation.send_client(b"GET /wrap?x=%3Cscript%3E HTTP/1.1\r\nHost: server\r\n\r\n", pieces=[6, 6, 100])
    conversation.send_server(HTTP_RESPONSE)
    return conversation.close().frames


def scenario_ip_fragment_xss() -> list[tuple[float, bytes]]:
    """XSS request whose TCP segment is cut into IP fragments sent in reverse order."""
    conversation = TcpConversation(client_port=40004).handshake()
    request = b"GET /comment?text=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1\r\nHost: victim\r\n\r\n"
    transport = conversation.client_transport(0, request)
    pieces = [(offset, 24) for offset in range(0, len(transport), 24)]
    for frame in reversed(fragment_frames(CLIENT_IP, SERVER_IP, 6, transport, 4242, pieces)):
        conversation.add(frame)
    conversation.client_sent = len(request)
    conversation.send_server(HTTP_RESPONSE)
    return conversation.close().frames


def scenario_ip_fragment_attacks() -> list[tuple[float, bytes]]:
    """Fragment anomalies: overlapping conflict, tiny first fragment, missing fragment."""
    frames = []
    start = 1_700_000_100.0
    payload = b"A" * 40
    udp = udp_datagram(CLIENT_IP, SERVER_IP, 5555, 53, payload)
    overlap = fragment_frames(
        CLIENT_IP, SERVER_IP, 17, udp, 7001,
        [(0, udp[:24], True), (16, b"BBBBBBBBBBBBBBBB", True), (24, udp[24:], False)],
    )
    conversation = TcpConversation(client_port=40005)
    tcp = conversation.client_transport(0, b"GET / HTTP/1.1\r\n\r\n", flags=TCP_PSH | TCP_ACK)
    tiny = fragment_frames(CLIENT_IP, SERVER_IP, 6, tcp, 7002, [(0, 8), (8, len(tcp) - 8)])
    missing = fragment_frames(CLIENT_IP, SERVER_IP, 17, udp, 7003, [(0, 16), (32, len(udp) - 32)])
    for index, frame in enumerate(overlap + tiny + missing):
        frames.append((start + index * 0.01, frame))
    return frames


def scenario_http_encoding_evasion() -> list[tuple[float, bytes]]:
    """Several encoded attacks in one keep-alive connection."""
    conversation = TcpConversation(client_port=40006).handshake()
    requests = [
        b"GET /item.php?id=1%2527%2520UNION%2520SELECT%2520password HTTP/1.1\r\nHost: victim\r\n\r\n",
        b"GET /item.php?id=1+UNION/**/SELECT/**/password HTTP/1.1\r\nHost: victim\r\n\r\n",
        b"GET /item.php?id=1+%u0055NION+/*!50000SELECT*/+1 HTTP/1.1\r\nHost: victim\r\n\r\n",
        b"GET /static/..%2f..%2f..%c0%afetc/passwd HTTP/1.1\r\nHost: victim\r\n\r\n",
        b"GET /ping?host=127.0.0.1;cat+/etc/passwd HTTP/1.1\r\nHost: victim\r\n\r\n",
        b"POST /login HTTP/1.1\r\nHost: victim\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n8\r\nuser=adm\r\n17\r\nin%27+OR+%271%27%3D%271\r\n0\r\n\r\n",
    ]
    for request in requests:
        conversation.send_client(request, pieces=[7, 13, len(request)])
        conversation.send_server(HTTP_RESPONSE)
    return conversation.close().frames


SCENARIOS = {
    "tcp_out_of_order_sqli": scenario_tcp_out_of_order_sqli,
    "tcp_overlap_conflict": scenario_tcp_overlap_conflict,
    "tcp_retransmission": scenario_tcp_retransmission,
    "tcp_seq_wraparound": scenario_tcp_seq_wraparound,
    "ip_fragment_xss": scenario_ip_fragment_xss,
    "ip_fragment_attacks": scenario_ip_fragment_attacks,
    "http_encoding_evasion": scenario_http_encoding_evasion,
}


def build_all(directory: Path) -> dict[str, Path]:
    return {name: write_pcap(Path(directory) / f"{name}.pcap", build()) for name, build in SCENARIOS.items()}
