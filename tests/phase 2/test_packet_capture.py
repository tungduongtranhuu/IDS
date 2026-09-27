import struct
import sys
import tempfile
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
PHASE_TWO_DIR = WORKSPACE_ROOT / "ids" / "phase 2"
sys.path.insert(0, str(PHASE_TWO_DIR))

from packet_capture import PcapWriter


CAPTURE_FILE = PHASE_TWO_DIR / "capture.pcap"


class PacketCaptureTests(unittest.TestCase):
    def test_writer_creates_readable_pcap(self):
        packet_data = bytes.fromhex("00112233445566778899aabb0800")

        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "test_capture.pcap"
            writer = PcapWriter(output)
            writer.write_packet(packet_data)
            writer.close()

            contents = output.read_bytes()

        self.assertEqual(len(contents), 24 + 16 + len(packet_data))
        self.assertEqual(contents[:4], bytes.fromhex("d4c3b2a1"))
        captured_length, wire_length = struct.unpack_from("<II", contents, 24 + 8)
        self.assertEqual(captured_length, len(packet_data))
        self.assertEqual(wire_length, len(packet_data))

    def test_existing_capture_file_has_pcap_header(self):
        self.assertTrue(CAPTURE_FILE.is_file(), f"Missing PCAP file: {CAPTURE_FILE}")
        self.assertGreaterEqual(CAPTURE_FILE.stat().st_size, 24)
        self.assertIn(
            CAPTURE_FILE.read_bytes()[:4],
            (bytes.fromhex("d4c3b2a1"), bytes.fromhex("a1b2c3d4")),
        )


if __name__ == "__main__":
    unittest.main()