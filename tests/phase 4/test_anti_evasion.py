"""End-to-end Phase 4 tests.

Synthetic evasion PCAPs are written to tests/phase 4/pcaps (open them in
Wireshark if you like), the CLI is run on them and on the BENIGN captures,
and every report is saved under tests/phase 4/results for reading.
"""

import subprocess
import sys
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
for directory in ("phase 2", "phase 3", "phase 4"):
    sys.path.insert(0, str(WORKSPACE_ROOT / "ids" / directory))

from anti_evasion import AntiEvasionPipeline, stream_requests
from pcap_factory import build_all


TEST_DIR = Path(__file__).resolve().parent
PCAP_DIR = TEST_DIR / "pcaps"
RESULTS_DIR = TEST_DIR / "results"
DATA_DIR = WORKSPACE_ROOT / "data"
ANTI_EVASION_FILE = WORKSPACE_ROOT / "ids" / "phase 4" / "anti_evasion.py"
BENIGN_PCAPS = (
    DATA_DIR / "BENIGN" / "HTTP" / "http_normal.pcap",
    DATA_DIR / "BENIGN" / "SSH" / "ssh_normal.pcap",
    DATA_DIR / "BENIGN" / "ICMP" / "icmp_normal.pcap",
)


def run_cli(pcap: Path, result_file: Path, mode="verbose", *extra) -> str:
    result_file.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable, "-W", "ignore", str(ANTI_EVASION_FILE), str(pcap),
        "--mode", mode, "--result", str(result_file), *extra,
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)
    return result_file.read_text(encoding="utf-8")


class ScenarioTests(unittest.TestCase):
    """One report per evasion scenario: results/<scenario>_<mode>.txt."""

    @classmethod
    def setUpClass(cls):
        cls.pcaps = build_all(PCAP_DIR)

    def report(self, scenario, mode="verbose", *extra, suffix=""):
        name = f"{scenario}{suffix}_{mode}.txt"
        return run_cli(self.pcaps[scenario], RESULTS_DIR / name, mode, *extra)

    def test_tcp_out_of_order_sqli(self):
        text = self.report("tcp_out_of_order_sqli")
        self.assertIn("TCP_OUT_OF_ORDER:1", text)
        self.assertIn("uri_normalized : /search.php?q=1' union select password from users--", text)

    def test_tcp_overlap_conflict_policy_first(self):
        text = self.report("tcp_overlap_conflict")
        self.assertIn("[SUSPICIOUS]", text)
        self.assertIn("TCP_OVERLAP_CONFLICT", text)
        self.assertIn("uri_normalized : /index.php?id=1 aaaaaaaaaaaaaaaer,pass from users", text)

    def test_tcp_overlap_conflict_policy_last(self):
        text = self.report("tcp_overlap_conflict", "verbose", "--overlap-policy", "last", suffix="_policy_last")
        self.assertIn("TCP_OVERLAP_CONFLICT", text)
        self.assertIn("uri_normalized : /index.php?id=1 union select user,pass from users", text)

    def test_tcp_retransmission_is_not_suspicious(self):
        text = self.report("tcp_retransmission")
        self.assertIn("TCP_RETRANSMISSION:2", text)
        self.assertNotIn("[SUSPICIOUS]", text)
        self.assertIn("uri_normalized : /index.html", text)

    def test_tcp_sequence_wraparound(self):
        text = self.report("tcp_seq_wraparound")
        self.assertIn("uri_normalized : /wrap?x=<script>", text)

    def test_ip_fragment_xss(self):
        text = self.report("ip_fragment_xss")
        self.assertIn("reassembled=1", text)
        self.assertIn("fragments=5", text)
        self.assertIn("uri_normalized : /comment?text=<script>alert(document.cookie)</script>", text)

    def test_ip_fragment_attacks(self):
        text = self.report("ip_fragment_attacks")
        for anomaly in ("FRAG_OVERLAP_CONFLICT", "FRAG_TINY_FIRST", "FRAG_TIMEOUT"):
            self.assertIn(f"IP defrag anomaly: {anomaly}", text)
        self.assertIn("missing bytes 16-32", text)
        self.assertIn("[SUSPICIOUS]", text)

    def test_http_encoding_evasion(self):
        text = self.report("http_encoding_evasion")
        expected = [
            "uri_normalized : /item.php?id=1' union select password",
            "uri_normalized : /item.php?id=1 union select password",
            "uri_normalized : /item.php?id=1 union select 1",
            "uri_normalized : /etc/passwd",
            "uri_normalized : /ping?host=127.0.0.1;cat /etc/passwd",
            "body_normalized: user=admin' or '1'='1",
        ]
        for line in expected:
            self.assertIn(line, text)
        for anomaly in ("DOUBLE_ENCODING", "SQL_COMMENT", "UNICODE_ENCODING", "OVERLONG_UTF8", "PATH_TRAVERSAL"):
            self.assertIn(anomaly, text)

    def test_debug_mode_shows_reassembled_bytes(self):
        text = self.report("tcp_out_of_order_sqli", "debug")
        self.assertIn("client data: GET /search.php?q=1%27+UNION+SELECT", text)
        self.assertIn("header Host: victim", text)

    def test_normal_mode_lists_only_suspicious_streams(self):
        clean = self.report("tcp_out_of_order_sqli", "normal")
        self.assertNotIn("Stream #", clean)
        self.assertIn("HTTP normalization: requests=1", clean)
        attack = self.report("tcp_overlap_conflict", "normal")
        self.assertIn("Stream #1 [SUSPICIOUS]", attack)

    def test_quiet_mode_writes_result_file(self):
        self.report("ip_fragment_xss", "quiet")
        self.assertTrue((RESULTS_DIR / "ip_fragment_xss_quiet.txt").is_file())


class BenignCaptureTests(unittest.TestCase):
    """Real benign traffic: reassembly works and nothing is flagged as suspicious."""

    def report(self, pcap: Path, mode: str) -> str:
        relative = pcap.relative_to(DATA_DIR)
        result = RESULTS_DIR / relative.parent / f"{relative.stem}_anti_evasion_{mode}.txt"
        return run_cli(pcap, result, mode)

    def test_benign_captures(self):
        for pcap in BENIGN_PCAPS:
            for mode in ("normal", "verbose"):
                with self.subTest(pcap=pcap.name, mode=mode):
                    self.assertTrue(pcap.is_file(), f"Missing PCAP file: {pcap}")
                    text = self.report(pcap, mode)
                    self.assertIn("TCP reassembly:", text)
                    self.assertNotIn("[SUSPICIOUS]", text)

    def test_http_requests_are_extracted(self):
        text = self.report(BENIGN_PCAPS[0], "verbose")
        self.assertIn("GET /login.php HTTP/1.1", text)
        self.assertIn("HTTP normalization: requests=4", text)


class PipelineApiTests(unittest.TestCase):
    """Use the pipeline from Python, as later phases will."""

    def test_streams_and_requests_are_available(self):
        pcaps = build_all(PCAP_DIR)
        streams = []
        pipeline = AntiEvasionPipeline(on_stream_end=streams.append)
        pipeline.run_pcap(pcaps["ip_fragment_xss"])
        pipeline.finish()
        self.assertEqual(len(streams), 1)
        stream = streams[0]
        self.assertEqual(stream.flow.fragment_count, 5)
        request = stream_requests(stream)[0]
        self.assertEqual(request.method, "GET")
        self.assertIn("<script>", request.uri_normalized)
        self.assertTrue(bytes(stream.client.data).startswith(b"GET /comment?text=%3Cscript%3E"))


if __name__ == "__main__":
    unittest.main()
