import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
PHASE_THREE_DIR = WORKSPACE_ROOT / "ids" / "phase 3"
DATA_DIR = WORKSPACE_ROOT / "data"
sys.path.insert(0, str(PHASE_THREE_DIR))

from flow_manager import (
    TCP_ACK,
    TCP_FIN,
    TCP_RST,
    TCP_SYN,
    FlowManager,
    FlowTimeouts,
)

PCAP_FILES = (
    WORKSPACE_ROOT / "data" / "BENIGN" / "SSH" / "ssh_normal.pcap",
    WORKSPACE_ROOT / "data" / "BENIGN" / "ICMP" / "icmp_normal.pcap",
    WORKSPACE_ROOT / "data" / "BENIGN" / "HTTP" / "http_normal.pcap",
)
RESULTS_DIR = Path(__file__).resolve().parent / "results"
FLOW_MANAGER_FILE = PHASE_THREE_DIR / "flow_manager.py"


CLIENT = ("10.0.0.1", 40000)
SERVER = ("10.0.0.2", 80)


def make_packet(timestamp, src=CLIENT, dst=SERVER, protocol="TCP", flags=0, **extra):
    """Build a fake decoded packet with the attributes FlowManager reads."""
    values = {
        "timestamp": timestamp,
        "src_ip": src[0],
        "src_port": src[1],
        "dst_ip": dst[0],
        "dst_port": dst[1],
        "ip_protocol": protocol,
        "capture_length": 60,
        "payload": b"",
        "tcp_flags": flags if protocol == "TCP" else None,
        "tcp_seq": 1000,
    }
    values.update(extra)
    return SimpleNamespace(**values)


def client_packet(timestamp, flags=0, **extra):
    return make_packet(timestamp, CLIENT, SERVER, flags=flags, **extra)


def server_packet(timestamp, flags=0, **extra):
    return make_packet(timestamp, SERVER, CLIENT, flags=flags, **extra)


def tcp_handshake(manager, start=0.0):
    flow = manager.add_packet(client_packet(start, TCP_SYN))
    manager.add_packet(server_packet(start + 0.1, TCP_SYN | TCP_ACK))
    manager.add_packet(client_packet(start + 0.2, TCP_ACK))
    return flow


class FlowLifecycleTests(unittest.TestCase):
    """Fix 1 and 2: flows end on timeout, RST, FIN and port reuse."""

    def test_idle_gap_starts_new_flow(self):
        manager = FlowManager(flow_timeout=60, keep_finished_flows=True)
        first = manager.add_packet(client_packet(0))
        second = manager.add_packet(client_packet(500))
        self.assertIsNot(first, second)
        self.assertEqual(first.termination_reason, "TIMEOUT")
        self.assertEqual(first.duration, 0)
        self.assertEqual(second.packet_count, 1)

    def test_rst_closes_flow_after_short_closed_timeout(self):
        manager = FlowManager(keep_finished_flows=True)
        flow = tcp_handshake(manager)
        manager.add_packet(server_packet(1, TCP_RST))
        self.assertEqual(flow.tcp_state, "CLOSED")
        # A trailing RST is absorbed instead of creating a ghost flow.
        self.assertIs(manager.add_packet(client_packet(1.1, TCP_RST)), flow)
        self.assertEqual(len(manager.flows), 1)
        self.assertEqual(manager.expire(1.1 + 2), [flow])
        self.assertEqual(flow.status, "CLOSED")
        self.assertEqual(flow.termination_reason, "TCP_RST")

    def test_new_syn_after_rst_starts_new_flow(self):
        manager = FlowManager(keep_finished_flows=True)
        flow = tcp_handshake(manager)
        manager.add_packet(server_packet(1, TCP_RST))
        new_flow = manager.add_packet(client_packet(1.5, TCP_SYN, tcp_seq=5000))
        self.assertIsNot(new_flow, flow)
        self.assertEqual(flow.termination_reason, "TCP_RST")
        self.assertEqual(new_flow.tcp_state, "SYN_SENT")

    def test_data_after_rst_is_counted(self):
        manager = FlowManager()
        flow = tcp_handshake(manager)
        manager.add_packet(server_packet(1, TCP_RST))
        manager.add_packet(client_packet(1.1, TCP_ACK, payload=b"still talking"))
        self.assertEqual(flow.packets_after_rst, 1)
        self.assertEqual(flow.tcp_state, "CLOSED")

    def test_both_fin_closes_after_short_closing_timeout(self):
        manager = FlowManager(keep_finished_flows=True)
        flow = tcp_handshake(manager)
        manager.add_packet(client_packet(1, TCP_FIN | TCP_ACK))
        manager.add_packet(server_packet(1.1, TCP_FIN | TCP_ACK))
        manager.add_packet(client_packet(1.2, TCP_ACK))
        self.assertEqual(flow.tcp_state, "CLOSING")
        self.assertEqual(manager.expire(1.2 + 4), [])
        self.assertEqual(manager.expire(1.2 + 5), [flow])
        self.assertEqual(flow.termination_reason, "TCP_FIN")
        self.assertEqual(flow.conn_state, "SF")

    def test_new_syn_after_fin_is_port_reuse(self):
        manager = FlowManager(keep_finished_flows=True)
        flow = tcp_handshake(manager)
        manager.add_packet(client_packet(1, TCP_FIN | TCP_ACK))
        new_flow = manager.add_packet(client_packet(1.5, TCP_SYN, tcp_seq=9999))
        self.assertIsNot(new_flow, flow)
        self.assertEqual(flow.termination_reason, "TCP_PORT_REUSE")

    def test_retransmitted_syn_stays_in_same_flow(self):
        manager = FlowManager()
        flow = manager.add_packet(client_packet(0, TCP_SYN))
        self.assertIs(manager.add_packet(client_packet(1, TCP_SYN)), flow)
        self.assertEqual(flow.tcp_flag_counts["SYN"], 2)


class DirectionTests(unittest.TestCase):
    """Fix 3: the client is the initiator and traffic is split fwd/bwd."""

    def test_client_is_syn_sender_even_with_high_server_port(self):
        manager = FlowManager()
        client = ("192.168.10.20", 33540)
        server = ("172.17.0.2", 3000)
        flow = manager.add_packet(make_packet(0, client, server, flags=TCP_SYN))
        manager.add_packet(make_packet(0.1, server, client, flags=TCP_SYN | TCP_ACK))
        self.assertEqual(flow.client, client)
        self.assertEqual(flow.server, server)
        self.assertIn("192.168.10.20:33540 -> 172.17.0.2:3000", flow.summary())

    def test_synack_first_means_destination_is_client(self):
        manager = FlowManager()
        flow = manager.add_packet(server_packet(0, TCP_SYN | TCP_ACK))
        self.assertEqual(flow.client, CLIENT)
        self.assertEqual(flow.bwd_packets, 1)

    def test_midstream_uses_lower_port_as_server(self):
        manager = FlowManager()
        flow = manager.add_packet(server_packet(0, TCP_ACK))
        self.assertEqual(flow.client, CLIENT)
        self.assertEqual(flow.tcp_state, "MIDSTREAM")

        server = ("192.168.10.30", 3000)
        client = ("192.168.10.20", 33542)
        flow = manager.add_packet(make_packet(1, server, client, flags=TCP_ACK))
        self.assertEqual(flow.server, server)

    def test_forward_and_backward_counters(self):
        manager = FlowManager()
        flow = tcp_handshake(manager)
        manager.add_packet(client_packet(1, TCP_ACK, payload=b"GET / HTTP/1.1\r\n"))
        manager.add_packet(server_packet(2, TCP_ACK, payload=b"HTTP/1.1 200 OK"))
        self.assertEqual((flow.fwd_packets, flow.bwd_packets), (3, 2))
        self.assertEqual(flow.fwd_payload_bytes, 16)
        self.assertEqual(flow.bwd_payload_bytes, 15)


class TcpFlagTests(unittest.TestCase):
    """Fix 4: flag counters, Zeek-like history and conn_state."""

    def finished_flow(self, packets):
        finished = []
        manager = FlowManager(on_flow_end=finished.append)
        for packet in packets:
            manager.add_packet(packet)
        manager.close_all()
        return finished[0]

    def test_unanswered_syn_is_s0(self):
        flow = self.finished_flow([client_packet(0, TCP_SYN)])
        self.assertEqual(flow.conn_state, "S0")
        self.assertEqual(flow.history, "S")

    def test_closed_port_is_rej(self):
        flow = self.finished_flow(
            [client_packet(0, TCP_SYN), server_packet(0.1, TCP_RST | TCP_ACK)]
        )
        self.assertEqual(flow.conn_state, "REJ")
        self.assertEqual(flow.history, "Sr")

    def test_syn_scan_on_open_port(self):
        flow = self.finished_flow(
            [
                client_packet(0, TCP_SYN),
                server_packet(0.1, TCP_SYN | TCP_ACK),
                client_packet(0.2, TCP_RST),
            ]
        )
        self.assertEqual(flow.conn_state, "RSTO")
        self.assertEqual(flow.tcp_flag_counts, {"SYN": 2, "ACK": 1, "RST": 1})

    def test_established_without_close_is_s1(self):
        manager = FlowManager()
        flow = tcp_handshake(manager)
        self.assertEqual(flow.tcp_state, "ESTABLISHED")
        self.assertTrue(flow.handshake_completed)
        self.assertEqual(flow.conn_state, "S1")

    def test_null_packets_are_counted(self):
        flow = self.finished_flow([client_packet(0, 0)])
        self.assertEqual(flow.tcp_flag_counts, {"NULL": 1})
        self.assertEqual(flow.conn_state, "OTH")


class MemoryTests(unittest.TestCase):
    """Fix 5: no unbounded packet or finished-flow storage."""

    def test_packets_and_finished_flows_not_kept_by_default(self):
        finished = []
        manager = FlowManager(on_flow_end=finished.append)
        flow = manager.add_packet(client_packet(0, TCP_SYN))
        manager.close_all()
        self.assertEqual(flow.packets, [])
        self.assertEqual(manager.expired_flows, [])
        self.assertEqual(finished, [flow])
        self.assertEqual(manager.statistics()["packets"], 1)

    def test_flow_keeps_no_payload_buffer(self):
        manager = FlowManager()
        flow = manager.add_packet(client_packet(0, TCP_ACK, payload=b"A" * 20))
        self.assertEqual(flow.fwd_payload_bytes, 20)
        self.assertFalse(hasattr(flow, "fwd_payload_sample"))

    def test_store_packets_for_debug(self):
        manager = FlowManager(store_packets=True)
        flow = manager.add_packet(client_packet(0))
        self.assertEqual(len(flow.packets), 1)


class PacketHookTests(unittest.TestCase):
    """on_packet hook: per-packet handoff to Phase 4 reassembly."""

    def test_hook_receives_flow_packet_and_direction(self):
        calls = []
        manager = FlowManager(
            on_packet=lambda flow, packet, is_forward: calls.append(
                (flow, packet, is_forward)
            )
        )
        syn = client_packet(0, TCP_SYN)
        synack = server_packet(0.1, TCP_SYN | TCP_ACK)
        flow = manager.add_packet(syn)
        manager.add_packet(synack)
        self.assertEqual(calls, [(flow, syn, True), (flow, synack, False)])

    def test_hook_sees_updated_flow_state(self):
        states = []
        manager = FlowManager(
            on_packet=lambda flow, packet, is_forward: states.append(flow.tcp_state)
        )
        tcp_handshake(manager)
        self.assertEqual(states, ["SYN_SENT", "SYN_RECEIVED", "ESTABLISHED"])

    def test_old_flow_ends_before_new_flow_gets_packet(self):
        events = []
        manager = FlowManager(
            on_packet=lambda flow, packet, is_forward: events.append(("packet", flow)),
            on_flow_end=lambda flow: events.append(("end", flow)),
        )
        old = tcp_handshake(manager)
        manager.add_packet(server_packet(1, TCP_RST))
        events.clear()
        new = manager.add_packet(client_packet(1.5, TCP_SYN, tcp_seq=5000))
        self.assertEqual(events, [("end", old), ("packet", new)])


class SweepTests(unittest.TestCase):
    """Fix 6: expiry runs periodically, not on every packet."""

    def test_sweep_runs_once_per_interval(self):
        manager = FlowManager(sweep_interval=1.0)
        for index in range(100):
            manager.add_packet(client_packet(index * 0.01))
        self.assertEqual(manager.sweeps, 0)
        manager.add_packet(client_packet(1.5))
        self.assertEqual(manager.sweeps, 1)

    def test_sweep_expires_other_idle_flows(self):
        finished = []
        manager = FlowManager(flow_timeout=10, on_flow_end=finished.append)
        old = manager.add_packet(client_packet(0))
        manager.add_packet(make_packet(20, ("10.0.0.9", 5000), SERVER))
        self.assertEqual(finished, [old])


class TimeoutTests(unittest.TestCase):
    """Fix 7: per-protocol idle timeouts and active timeout."""

    def test_default_timeouts_depend_on_protocol_and_state(self):
        manager = FlowManager()
        udp = manager.add_packet(
            make_packet(0, ("10.0.0.1", 5353), ("10.0.0.2", 53), protocol="UDP")
        )
        syn_only = manager.add_packet(
            make_packet(0, ("10.0.0.1", 1), SERVER, flags=TCP_SYN)
        )
        established = tcp_handshake(manager)
        expired = manager.expire(40)
        self.assertIn(syn_only, expired)
        self.assertNotIn(udp, expired)
        self.assertNotIn(established, expired)
        self.assertIn(udp, manager.expire(61))
        self.assertIn(established, manager.expire(301))

    def test_active_timeout_splits_long_flow_and_keeps_direction(self):
        manager = FlowManager(active_timeout=120, keep_finished_flows=True)
        first = tcp_handshake(manager)
        for second in range(10, 130, 10):
            current = manager.add_packet(server_packet(second, TCP_ACK, payload=b"x"))
        self.assertEqual(first.termination_reason, "ACTIVE_TIMEOUT")
        self.assertIsNot(current, first)
        self.assertTrue(current.is_continuation)
        self.assertEqual(current.client, CLIENT)
        self.assertEqual(current.tcp_state, "ESTABLISHED")

    def test_invalid_timeouts_rejected(self):
        invalid_arguments = (
            {"flow_timeout": 0},
            {"timeouts": FlowTimeouts(udp=0)},
            {"active_timeout": -1},
        )
        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                self.assertRaises(ValueError, FlowManager, **arguments)


class FragmentIcmpSizeTests(unittest.TestCase):
    """Fix 8: fragments (now reassembled by Phase 4), ICMP identifiers, byte counts."""

    def test_non_first_fragment_is_ignored_and_counted(self):
        manager = FlowManager()
        fragment = make_packet(
            0,
            (CLIENT[0], None),
            (SERVER[0], None),
            protocol="UDP",
            fragment_offset=185,
            more_fragments=False,
        )
        self.assertIsNone(manager.add_packet(fragment))
        self.assertEqual(manager.flows, {})
        self.assertEqual(manager.statistics()["ignored_fragments"], 1)

    def test_reassembled_packet_counts_its_fragments(self):
        manager = FlowManager()
        flow = manager.add_packet(
            make_packet(0, protocol="UDP", reassembled_fragments=3, ip_total_length=4000)
        )
        self.assertEqual(flow.fragment_count, 3)
        self.assertEqual(flow.packet_count, 1)
        self.assertEqual(flow.byte_count, 4000)
        self.assertIn("fragments=3", flow.summary())

    def test_icmp_identifier_separates_ping_sessions(self):
        manager = FlowManager()
        client_host = (CLIENT[0], None)
        server_host = (SERVER[0], None)

        def ping(timestamp, identifier, icmp_type=8):
            src, dst = (server_host, client_host) if icmp_type == 0 else (
                client_host,
                server_host,
            )
            return make_packet(
                timestamp,
                src,
                dst,
                protocol="ICMP",
                icmp_type=icmp_type,
                icmp_identifier=identifier,
            )

        first = manager.add_packet(ping(0, 1))
        reply = manager.add_packet(ping(0.1, 1, icmp_type=0))
        second = manager.add_packet(ping(1, 2))
        self.assertIs(first, reply)
        self.assertIsNot(first, second)
        self.assertEqual(first.conn_state, "SF")

    def test_byte_count_uses_ip_total_length(self):
        manager = FlowManager()
        flow = manager.add_packet(
            client_packet(0, TCP_SYN, ip_total_length=40, wire_length=54, capture_length=54)
        )
        self.assertEqual(flow.byte_count, 40)


class FlowManagerTests(unittest.TestCase):
    def test_expire_returns_only_newly_expired_flows(self):
        manager = FlowManager(flow_timeout=10, keep_finished_flows=True)

        def packet(timestamp, source_port):
            return SimpleNamespace(
                timestamp=timestamp,
                src_ip="192.0.2.1",
                src_port=source_port,
                dst_ip="192.0.2.2",
                dst_port=80,
                ip_protocol="TCP",
                capture_length=60,
                payload=b"",
                tcp_flags=0,
            )

        flow_a = manager.add_packet(packet(100, 1000))
        self.assertEqual(manager.expire(109), [])
        expired_a = manager.expire(111)
        self.assertEqual(expired_a, [flow_a])
        self.assertEqual(flow_a.status, "EXPIRED")
        self.assertEqual(flow_a.termination_reason, "TIMEOUT")

        flow_b = manager.add_packet(packet(200, 2000))
        expired_b = manager.expire(211)
        self.assertEqual(expired_b, [flow_b])
        self.assertEqual(manager.expired_flows, [flow_a, flow_b])
    def get_result_path(self, pcap_file, mode, packet_limit=None):
        relative_path = pcap_file.resolve().relative_to(DATA_DIR.resolve())
        limit_suffix = f"_{packet_limit}" if packet_limit is not None else ""
        return (
            RESULTS_DIR
            / relative_path.parent
            / f"{relative_path.stem}_flow_{mode}{limit_suffix}.txt"
        )

    def run_flow_manager(self, pcap_file, mode, packet_limit=None):
        self.assertTrue(pcap_file.is_file(), f"Missing PCAP file: {pcap_file}")
        result_file = self.get_result_path(pcap_file, mode, packet_limit)
        result_file.parent.mkdir(parents=True, exist_ok=True)
        command = [
            sys.executable,
            str(FLOW_MANAGER_FILE),
            str(pcap_file),
            "--mode",
            mode,
            "--timeout",
            "60",
            "--result",
            str(result_file),
        ]
        if packet_limit is not None:
            command.extend(["--limit", str(packet_limit)])

        completed_process = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed_process.returncode, 0)
        self.assertTrue(result_file.is_file())
        return result_file.read_text(encoding="utf-8")

    def test_normal_mode_writes_flow_statistics(self):
        for pcap_file in PCAP_FILES:
            with self.subTest(pcap=pcap_file.name):
                result = self.run_flow_manager(pcap_file, "normal")
                self.assertIn("Flow statistics:", result)

    def test_quiet_mode_writes_result_file(self):
        for pcap_file in PCAP_FILES:
            with self.subTest(pcap=pcap_file.name):
                result_file = self.get_result_path(pcap_file, "quiet")
                self.run_flow_manager(pcap_file, "quiet")
                self.assertTrue(result_file.is_file())

    def test_verbose_mode_writes_flow_summaries(self):
        for pcap_file in PCAP_FILES:
            with self.subTest(pcap=pcap_file.name):
                result = self.run_flow_manager(pcap_file, "verbose")
                self.assertIn("Flow #1:", result)

    def test_debug_mode_writes_packet_details(self):
        for pcap_file in PCAP_FILES:
            with self.subTest(pcap=pcap_file.name):
                result = self.run_flow_manager(pcap_file, "debug")
                self.assertIn("Flow #1:", result)
                self.assertIn("packet #1:", result)


if __name__ == "__main__":
    unittest.main()
