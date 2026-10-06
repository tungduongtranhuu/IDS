import argparse
import subprocess
import sys
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
PHASE_TWO_DIR = WORKSPACE_ROOT / "ids" / "phase 2"


CAPTURE_FILE = WORKSPACE_ROOT / "data" / "BENIGN" / "ICMP" / "icmp_normal.pcap"
DATA_DIR = WORKSPACE_ROOT / "data"
RESULTS_DIR = Path(__file__).resolve().parent / "results_decode"
RESULT_FILE = RESULTS_DIR / "packet_decoder_result.txt"
MODES = ("quiet", "normal", "verbose", "debug")


def get_result_path(pcap_file, mode):
    """Mirror the PCAP's path under data/ in the decoder result directory."""
    pcap_path = Path(pcap_file).resolve()
    try:
        relative_path = pcap_path.relative_to(DATA_DIR.resolve())
    except ValueError as error:
        raise ValueError(f"PCAP must be inside {DATA_DIR}") from error

    return RESULTS_DIR / relative_path.parent / f"{relative_path.stem}_{mode}.txt"


def run_decoder(pcap_file, mode):
    """Run packet_decode.py once and return its result file path."""
    pcap_path = Path(pcap_file).resolve()
    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    if pcap_path.suffix.lower() != ".pcap":
        raise ValueError(f"Input file must have a .pcap extension: {pcap_path}")

    result_file = get_result_path(pcap_path, mode)
    result_file.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            str(PHASE_TWO_DIR / "packet_decode.py"),
            str(pcap_path),
            "--mode",
            mode,
            "--result",
            str(result_file),
        ],
        check=True,
    )
    return result_file


def run_cli(arguments):
    parser = argparse.ArgumentParser(
        description="Run packet_decode.py for a PCAP under data/"
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="PCAP path, relative to the project root or an absolute path under data/",
    )
    parser.add_argument(
        "--mode",
        choices=(*MODES, "all"),
        default="all",
        help="Decoder mode to run; default: all four modes",
    )
    args = parser.parse_args(arguments)
    modes = MODES if args.mode == "all" else (args.mode,)

    for mode in modes:
        result_file = run_decoder(args.pcap, mode)
        print(f"{mode}: {result_file.relative_to(WORKSPACE_ROOT)}")


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
    if "--pcap" in sys.argv:
        run_cli(sys.argv[1:])
    else:
        unittest.main()