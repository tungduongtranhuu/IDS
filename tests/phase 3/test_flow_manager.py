import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
PHASE_THREE_DIR = WORKSPACE_ROOT / "ids" / "phase 3"
DATA_DIR = WORKSPACE_ROOT / "data"
sys.path.insert(0, str(PHASE_THREE_DIR))

from flow_manager import FlowManager

PCAP_FILES = (
    WORKSPACE_ROOT / "data" / "BENIGN" / "SSH" / "ssh_normal.pcap",
    WORKSPACE_ROOT / "data" / "BENIGN" / "ICMP" / "icmp_normal.pcap",
    WORKSPACE_ROOT / "data" / "BENIGN" / "HTTP" / "http_normal.pcap",
)
RESULTS_DIR = Path(__file__).resolve().parent / "results"
FLOW_MANAGER_FILE = PHASE_THREE_DIR / "flow_manager.py"


class FlowManagerTests(unittest.TestCase):
    def test_expire_returns_only_newly_expired_flows(self):
        manager = FlowManager(flow_timeout=10)

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
