import subprocess
import sys
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
PHASE_TWO_DIR = WORKSPACE_ROOT / "ids" / "phase 2"
PHASE_THREE_DIR = WORKSPACE_ROOT / "ids" / "phase 3"

CAPTURE_FILE = PHASE_TWO_DIR / "capture.pcap"
RESULTS_DIR = Path(__file__).resolve().parent / "results"
FLOW_MANAGER_FILE = PHASE_THREE_DIR / "flow_manager.py"


class FlowManagerTests(unittest.TestCase):
    def run_flow_manager(self, mode, filename, packet_limit=None):
        self.assertTrue(CAPTURE_FILE.is_file(), f"Missing PCAP file: {CAPTURE_FILE}")
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        result_file = RESULTS_DIR / filename
        command = [
            sys.executable,
            str(FLOW_MANAGER_FILE),
            str(CAPTURE_FILE),
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
        result = self.run_flow_manager("normal", "flow_normal.txt")
        self.assertIn("Flow statistics:", result)

    def test_verbose_mode_writes_flow_summaries(self):
        result = self.run_flow_manager("verbose", "flow_verbose.txt", packet_limit=20)
        self.assertIn("Flow #1:", result)

    def test_debug_mode_writes_packet_details(self):
        result = self.run_flow_manager("debug", "flow_debug.txt", packet_limit=20)
        self.assertIn("Flow #1:", result)
        self.assertIn("packet #1:", result)


if __name__ == "__main__":
    unittest.main()
