"""Synthetic PCAPs that imitate the 12 dataset scenarios (dataset/attack_runner.sh).

The real captures in data/ are made in the lab; until they exist, these files
reproduce the same traffic shapes byte by byte so the rule engine can be
checked end to end:

    syn_scan      nmap -sS        one source port, SYN -> SYN-ACK -> RST (never completes)
    port_scan     nmap -sT -p 1-100   full handshake on open ports, then RST
    service_scan  nmap -sV        connect scan of ~1000 ports, then banner grabs / probes
    icmp_flood    hping3 --icmp --flood   ~1500 echo requests per second for 2 s
    dns_anomaly   30 x dig <32 random hex>.example.com
    ...

The helpers of tests/phase 4/pcap_factory.py are reused for the packet bytes.
"""

import random
import struct
import sys
from pathlib import Path


PHASE_FOUR_TESTS = Path(__file__).resolve().parents[1] / "phase 4"
if str(PHASE_FOUR_TESTS) not in sys.path:
    sys.path.insert(0, str(PHASE_FOUR_TESTS))

from pcap_factory import (
    HTTP_RESPONSE,
    SCENARIOS as EVASION_SCENARIOS,
    TCP_ACK,
    TCP_RST,
    TCP_SYN,
    TcpConversation,
    checksum,
    ethernet,
    ipv4,
    tcp_segment,
    udp_datagram,
    write_pcap,
)


GENERATOR = "192.168.100.10"
VICTIM = "192.168.100.30"
GENERATOR_MAC = bytes.fromhex("08002700000a")
VICTIM_MAC = bytes.fromhex("08002700001e")
START = 1_760_000_000.0
OPEN_PORTS = (22, 53, 80, 3000)
SSH_BANNER = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"

Frames = list[tuple[float, bytes]]


def _macs(src: str) -> tuple[bytes, bytes]:
    return (GENERATOR_MAC, VICTIM_MAC) if src == GENERATOR else (VICTIM_MAC, GENERATOR_MAC)


def tcp_frame(src, dst, sport, dport, seq, ack, flags, payload=b"", ip_id=1) -> bytes:
    src_mac, dst_mac = _macs(src)
    segment = tcp_segment(src, dst, sport, dport, seq, ack, flags, payload)
    return ethernet(ipv4(src, dst, 6, segment, ip_id), src_mac, dst_mac)


def udp_frame(src, dst, sport, dport, payload: bytes, ip_id=1) -> bytes:
    src_mac, dst_mac = _macs(src)
    return ethernet(ipv4(src, dst, 17, udp_datagram(src, dst, sport, dport, payload), ip_id), src_mac, dst_mac)


def icmp_frame(src, dst, icmp_type, identifier, sequence, payload=bytes(range(48)), ip_id=1) -> bytes:
    header = struct.pack("!BBHHH", icmp_type, 0, 0, identifier, sequence)
    value = checksum(header + payload)
    message = header[:2] + struct.pack("!H", value) + header[4:] + payload
    src_mac, dst_mac = _macs(src)
    return ethernet(ipv4(src, dst, 1, message, ip_id), src_mac, dst_mac)


def dns_message(query_id: int, name: str, response=False, rcode=0, qtype=1, qclass=1) -> bytes:
    flags = (0x8180 | rcode) if response else 0x0100
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0) + question + struct.pack("!HH", qtype, qclass)


def curl_request(path: str, host: str = VICTIM) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.11.0\r\nAccept: */*\r\n\r\n"
    ).encode()


def conversation(client_port, server_port, start, step=0.0005) -> TcpConversation:
    """TcpConversation from the lab generator to the victim."""
    return TcpConversation(
        client_port=client_port,
        server_port=server_port,
        client_ip=GENERATOR,
        server_ip=VICTIM,
        start=start,
        step=step,
    )


def http_exchange(path: str, client_port: int, start: float) -> Frames:
    conv = conversation(client_port, 80, start).handshake()
    conv.send_client(curl_request(path))
    conv.send_server(HTTP_RESPONSE)
    return conv.close().frames


def sorted_frames(*groups: Frames) -> Frames:
    return sorted((frame for group in groups for frame in group), key=lambda item: item[0])


# --------------------------------------------------------------- BENIGN
def scenario_benign_icmp() -> Frames:
    frames = []
    for sequence in range(1, 11):
        timestamp = START + sequence - 1
        frames.append((timestamp, icmp_frame(GENERATOR, VICTIM, 8, 0x3A5F, sequence, ip_id=sequence)))
        frames.append((timestamp + 0.0004, icmp_frame(VICTIM, GENERATOR, 0, 0x3A5F, sequence, ip_id=900 + sequence)))
    return frames


def scenario_benign_http() -> Frames:
    paths = ("/", "/index.php?id=1", "/index.html")
    return sorted_frames(*(http_exchange(path, 41000 + index, START + index) for index, path in enumerate(paths)))


def scenario_benign_ssh() -> Frames:
    rng = random.Random(22)
    conv = conversation(42000, 22, START, step=0.01).handshake()
    conv.send_server(SSH_BANNER)
    conv.send_client(b"SSH-2.0-OpenSSH_9.9p1 Debian-1\r\n")
    for size in (1200, 900, 48, 64, 300, 600, 80, 1400, 52):
        conv.send_client(rng.randbytes(size))
        conv.send_server(rng.randbytes(size + 32))
    return conv.close().frames


def scenario_benign_dns() -> Frames:
    frames = []
    for index, name in enumerate(("example.com", "test.local")):
        timestamp = START + index * 2
        sport = 50000 + index
        frames.append((timestamp, udp_frame(GENERATOR, VICTIM, sport, 53, dns_message(0x1000 + index, name))))
        response = dns_message(0x1000 + index, name, response=True)
        frames.append((timestamp + 0.002, udp_frame(VICTIM, GENERATOR, 53, sport, response)))
    return frames


# ---------------------------------------------------------------- RECON
def _scan_ports(count: int, seed: int) -> list[int]:
    rng = random.Random(seed)
    ports = set(OPEN_PORTS) | {443}
    while len(ports) < count:
        ports.add(rng.randint(1, 65535))
    ordered = sorted(ports)
    rng.shuffle(ordered)
    return ordered


def syn_scan_frames(ports, start, interval=0.001, source_port=61234) -> Frames:
    """nmap -sS: raw SYN from one source port; open ports answered with SYN-ACK, then RST."""
    frames = []
    for index, port in enumerate(ports):
        timestamp = start + index * interval
        seq = 0x10000000 + index
        frames.append((timestamp, tcp_frame(GENERATOR, VICTIM, source_port, port, seq, 0, TCP_SYN)))
        if port in OPEN_PORTS:
            frames.append((timestamp + 0.0002, tcp_frame(VICTIM, GENERATOR, port, source_port, 7000, seq + 1, TCP_SYN | TCP_ACK)))
            frames.append((timestamp + 0.0003, tcp_frame(GENERATOR, VICTIM, source_port, port, seq + 1, 0, TCP_RST)))
        else:
            frames.append((timestamp + 0.0002, tcp_frame(VICTIM, GENERATOR, port, source_port, 0, seq + 1, TCP_RST | TCP_ACK)))
    return frames


def connect_scan_frames(ports, start, interval=0.001, first_source_port=45000) -> Frames:
    """nmap -sT: connect() per port; open ports complete the handshake, then nmap sends RST."""
    frames = []
    for index, port in enumerate(ports):
        timestamp = start + index * interval
        sport = first_source_port + index
        seq = 0x20000000 + index * 1000
        frames.append((timestamp, tcp_frame(GENERATOR, VICTIM, sport, port, seq, 0, TCP_SYN)))
        if port in OPEN_PORTS:
            frames.append((timestamp + 0.0002, tcp_frame(VICTIM, GENERATOR, port, sport, 9000, seq + 1, TCP_SYN | TCP_ACK)))
            frames.append((timestamp + 0.0003, tcp_frame(GENERATOR, VICTIM, sport, port, seq + 1, 9001, TCP_ACK)))
            frames.append((timestamp + 0.0004, tcp_frame(GENERATOR, VICTIM, sport, port, seq + 1, 9001, TCP_RST | TCP_ACK)))
        else:
            frames.append((timestamp + 0.0002, tcp_frame(VICTIM, GENERATOR, port, sport, 0, seq + 1, TCP_RST | TCP_ACK)))
    return frames


def scenario_syn_scan() -> Frames:
    return syn_scan_frames(_scan_ports(1000, seed=2), START)


def scenario_port_scan() -> Frames:
    ports = list(range(1, 101))
    random.Random(3).shuffle(ports)
    return connect_scan_frames(ports, START)


def _delayed_close(conv: TcpConversation, delay: float) -> Frames:
    """Close a connection `delay` seconds after its last frame (nmap waiting for a banner)."""
    opened = len(conv.frames)
    conv.close()
    return [
        (timestamp + delay if index >= opened else timestamp, frame)
        for index, (timestamp, frame) in enumerate(conv.frames)
    ]


def scenario_service_scan() -> Frames:
    """nmap -sV as a normal user: connect scan, then service detection on open ports."""
    discovery = connect_scan_frames([80, 443], START, first_source_port=44000)
    scan = connect_scan_frames(_scan_ports(1000, seed=8), START + 0.05, first_source_port=46000)
    probes_start = START + 1.5
    groups = [discovery, scan]

    ssh = conversation(50022, 22, probes_start).handshake()
    ssh.send_server(SSH_BANNER)
    groups.append(ssh.close().frames)

    dns = conversation(50053, 53, probes_start + 0.01).handshake()
    version_bind = dns_message(0x0006, "version.bind", qtype=16, qclass=3)
    dns.send_client(struct.pack("!H", len(version_bind)) + version_bind)
    dns.send_server(b"\x00\x2a" + dns_message(0x0006, "version.bind", response=True, qtype=16, qclass=3))
    groups.append(dns.close().frames)

    for offset, port in enumerate((80, 3000)):
        # NULL probe: connect, wait 6 s for a banner that never comes, close.
        null_probe = conversation(50080 + offset, port, probes_start + 0.02 + offset * 0.01).handshake()
        groups.append(_delayed_close(null_probe, 6.0))
        # GetRequest probe on a new connection.
        get = conversation(50180 + offset, port, probes_start + 6.1 + offset * 0.01).handshake()
        get.send_client(b"GET / HTTP/1.0\r\n\r\n")
        get.send_server(HTTP_RESPONSE)
        groups.append(get.close().frames)
    return sorted_frames(*groups)


# ------------------------------------------------------------------ WEB
def scenario_sql_injection() -> Frames:
    return http_exchange("/index.php?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users", 43001, START)


def scenario_command_injection() -> Frames:
    return http_exchange("/ping.php?host=127.0.0.1;cat+/etc/passwd", 43003, START)


def scenario_xss() -> Frames:
    return http_exchange("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 43004, START)


# -------------------------------------------------------------- ANOMALY
def scenario_icmp_flood(rate: int = 1500, seconds: float = 2.0) -> Frames:
    frames = []
    for sequence in range(int(rate * seconds)):
        timestamp = START + sequence / rate
        frames.append((timestamp, icmp_frame(GENERATOR, VICTIM, 8, 0x4D2, sequence & 0xFFFF, bytes(16), ip_id=sequence & 0xFFFF)))
        frames.append((timestamp + 0.0001, icmp_frame(VICTIM, GENERATOR, 0, 0x4D2, sequence & 0xFFFF, bytes(16), ip_id=sequence & 0xFFFF)))
    return frames


def scenario_dns_anomaly(queries: int = 30) -> Frames:
    rng = random.Random(10)
    frames = []
    for index in range(queries):
        name = f"{rng.randbytes(16).hex()}.example.com"
        timestamp = START + index * 0.08
        sport = 52000 + index
        frames.append((timestamp, udp_frame(GENERATOR, VICTIM, sport, 53, dns_message(index, name))))
        response = dns_message(index, name, response=True, rcode=3)
        frames.append((timestamp + 0.003, udp_frame(VICTIM, GENERATOR, 53, sport, response)))
    return frames


SCENARIOS = {
    "benign_icmp": scenario_benign_icmp,
    "benign_http": scenario_benign_http,
    "benign_ssh": scenario_benign_ssh,
    "benign_dns": scenario_benign_dns,
    "syn_scan": scenario_syn_scan,
    "port_scan": scenario_port_scan,
    "service_scan": scenario_service_scan,
    "sql_injection": scenario_sql_injection,
    "command_injection": scenario_command_injection,
    "xss": scenario_xss,
    "icmp_flood": scenario_icmp_flood,
    "dns_anomaly": scenario_dns_anomaly,
}


def build_all(directory: Path) -> dict[str, Path]:
    """Write the 12 dataset scenarios plus the Phase 4 evasion PCAPs (prefix evasion_)."""
    directory = Path(directory)
    paths = {name: write_pcap(directory / f"{name}.pcap", build()) for name, build in SCENARIOS.items()}
    for name, build in EVASION_SCENARIOS.items():
        paths[f"evasion_{name}"] = write_pcap(directory / f"evasion_{name}.pcap", build())
    return paths
