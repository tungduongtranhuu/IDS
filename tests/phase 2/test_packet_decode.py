import subprocess
import sys
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
PHASE_TWO_DIR = WORKSPACE_ROOT / "ids" / "phase 2"


CAPTURE_FILE = PHASE_TWO_DIR / "capture.pcap"
RESULTS_DIR = Path(__file__).resolve().parent / "results"
RESULT_FILE = RESULTS_DIR / "packet_decoder_result.txt"


class PacketDecodeTests(unittest.TestCase):
    def test_decode_capture_and_write_result(self):
        self.assertTrue(CAPTURE_FILE.is_file(), f"Missing PCAP file: {CAPTURE_FILE}")

        completed_process = subprocess.run(
            [
                sys.executable,
                str(PHASE_TWO_DIR / "packet_decode.py"),
                str(CAPTURE_FILE),
                "--mode",
                "debug",
                "--result",
                str(RESULT_FILE),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed_process.returncode, 0)
        self.assertTrue(RESULT_FILE.is_file())
        result = RESULT_FILE.read_text(encoding="utf-8")
        self.assertIn("Packet #1", result)
        self.assertIn("capture:", result)
        self.assertIn("ethernet:", result)
        self.assertIn("ip:", result)
        self.assertIn("tcp:", result)
        self.assertIn("udp:", result)
        self.assertIn("icmp:", result)
        self.assertIn("flow: five_tuple=", result)
        self.assertIn("payload: length=", result)
        self.assertIn("Decoded packets:", result)


if __name__ == "__main__":
    unittest.main()