"""End-to-end Phase 5 tests on synthetic PCAPs and the real BENIGN captures.

Synthetic PCAPs (scenario_factory.py) are written to tests/phase 5/pcaps and
every report goes to tests/phase 5/results/<scenario>_<mode>.txt (+ .jsonl).
"""

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


TEST_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = TEST_DIR.parents[1]
for directory in ("phase 2", "phase 3", "phase 4", "phase 5"):
    sys.path.insert(0, str(WORKSPACE_ROOT / "ids" / directory))
sys.path.insert(0, str(TEST_DIR))

from ground_truth import GROUND_TRUTH, PCAP_GLOBAL_HEADER_BYTES, expected_sids
from pcap_factory import write_pcap
from rule_engine import DetectionPipeline, detect_pcap
from rule_loader import load_rules
from scenario_factory import (
    GENERATOR,
    START,
    VICTIM,
    conversation,
    curl_request,
    dns_message,
    icmp_frame,
    scenario_icmp_flood,
    syn_scan_frames,
    udp_frame,
)
import scenario_factory


PCAP_DIR = TEST_DIR / "pcaps"
RESULTS_DIR = TEST_DIR / "results"
DATA_DIR = WORKSPACE_ROOT / "data"
RULE_ENGINE_FILE = WORKSPACE_ROOT / "ids" / "phase 5" / "rule_engine.py"


def run_cli(*arguments) -> subprocess.CompletedProcess:
    command = [sys.executable, "-W", "ignore", str(RULE_ENGINE_FILE), *map(str, arguments)]
    return subprocess.run(command, capture_output=True, text=True)


def report(pcap: Path, name: str, mode="verbose", *extra) -> tuple[str, list[dict]]:
    result = RESULTS_DIR / f"{name}_{mode}.txt"
    alerts = RESULTS_DIR / f"{name}_{mode}.jsonl"
    result.parent.mkdir(parents=True, exist_ok=True)
    completed = run_cli(pcap, "--mode", mode, "--result", result, "--alerts", alerts, *extra)
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    lines = alerts.read_text(encoding="utf-8").splitlines()
    return result.read_text(encoding="utf-8"), [json.loads(line) for line in lines]


def sids_of(alerts) -> list[int]:
    return sorted(alert.sid for alert in alerts)


class DatasetScenarioTests(unittest.TestCase):
    """The 13 dataset scenarios, synthesized: each gives exactly its ground-truth SID."""

    @classmethod
    def setUpClass(cls):
        cls.pcaps = scenario_factory.build_all(PCAP_DIR)
        cls.rules = load_rules()

    def test_ground_truth_on_synthetic_scenarios(self):
        for scenario in GROUND_TRUTH:
            with self.subTest(scenario=scenario):
                alerts = detect_pcap(self.pcaps[scenario], self.rules).alerts
                expected = expected_sids(scenario)
                self.assertEqual({alert.sid for alert in alerts}, expected)
                self.assertEqual(len(alerts), len(expected), [alert.summary() for alert in alerts])

    def test_cli_reports_and_json_alerts(self):
        for scenario in GROUND_TRUTH:
            with self.subTest(scenario=scenario):
                text, alerts = report(self.pcaps[scenario], scenario)
                self.assertIn("CUSTOM IDS - PHASE 5 RULE ENGINE", text)
                self.assertEqual({alert["rule"]["id"] for alert in alerts}, expected_sids(scenario))
                for alert in alerts:
                    self.assertIn(f"sid={alert['rule']['id']}", text)

    def test_scan_evidence(self):
        _text, alerts = report(self.pcaps["syn_scan"], "syn_scan", "normal")
        evidence = alerts[0]["evidence"]
        self.assertEqual(alerts[0]["source"]["ip"], GENERATOR)
        self.assertEqual(alerts[0]["destination"]["ip"], VICTIM)
        self.assertEqual(evidence["technique"], "half_open")
        self.assertEqual(evidence["ports_probed"], 1000)
        self.assertEqual(evidence["handshakes_completed"], 0)

        service = detect_pcap(self.pcaps["service_scan"], self.rules).alerts[0].evidence
        self.assertEqual(service["technique"], "service")
        self.assertEqual(service["service_ports"], [53, 80, 3000])

    def test_web_evidence_keeps_raw_and_normalized(self):
        _text, alerts = report(self.pcaps["xss"], "xss", "normal")
        evidence = alerts[0]["evidence"]
        self.assertEqual(evidence["uri_raw"], "/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertEqual(evidence["uri_normalized"], "/search?q=<script>alert(1)</script>")
        self.assertEqual(evidence["matches"][0]["buffer"], "http_uri")
        self.assertEqual(alerts[0]["destination"]["port"], 80)

    def test_sql_evasion_reports_one_alert(self):
        alerts = detect_pcap(self.pcaps["sql_evasion"], self.rules).alerts
        self.assertEqual(sids_of(alerts), [10005])
        self.assertEqual(alerts[0].evidence["superseded_sids"], [10004])
        self.assertEqual(alerts[0].evidence["matches"][0]["matched"], "UNION/**/SELECT")

    def test_debug_mode_lists_buffers_and_episodes(self):
        text, _alerts = report(self.pcaps["service_scan"], "service_scan", "debug")
        self.assertIn("Scan episode 192.168.100.10 -> 192.168.100.30: technique=service", text)
        text, _alerts = report(self.pcaps["command_injection"], "command_injection", "debug")
        self.assertIn("http_uri = /ping.php?host=127.0.0.1;cat /etc/passwd", text)

    def test_quiet_mode_still_writes_alert_file(self):
        text, alerts = report(self.pcaps["icmp_flood"], "icmp_flood", "quiet")
        self.assertNotIn("ALERT", text)
        self.assertEqual([alert["rule"]["id"] for alert in alerts], [10009])


class EvasionTests(unittest.TestCase):
    """Phase 4 evasion PCAPs: alerts survive reassembly and normalization."""

    @classmethod
    def setUpClass(cls):
        cls.pcaps = scenario_factory.build_all(PCAP_DIR)
        cls.rules = load_rules()

    def sids(self, name, **options):
        return sids_of(detect_pcap(self.pcaps[f"evasion_{name}"], self.rules, **options).alerts)

    def test_out_of_order_segments(self):
        self.assertEqual(self.sids("tcp_out_of_order_sqli"), [10004])

    def test_ip_fragments_and_sequence_wraparound(self):
        self.assertEqual(self.sids("ip_fragment_xss"), [10007])
        self.assertEqual(self.sids("tcp_seq_wraparound"), [10007])

    def test_encoding_evasions(self):
        # double encoding -> 10004; UNION/**/SELECT and /*!50000SELECT*/ -> 10005 (supersedes 10004);
        # ..%2f + %c0%af -> /etc/passwd and ;cat -> 10006; the OR '1'='1 body has no rule yet.
        self.assertEqual(self.sids("http_encoding_evasion"), [10004, 10005, 10005, 10006, 10006])

    def test_overlap_policy_decides_what_is_seen(self):
        self.assertEqual(self.sids("tcp_overlap_conflict"), [])
        self.assertEqual(self.sids("tcp_overlap_conflict", overlap_policy="last"), [10004])

    def test_benign_retransmission(self):
        self.assertEqual(self.sids("tcp_retransmission"), [])


class EngineBehaviorTests(unittest.TestCase):
    """Thresholds, suppression, supersedes and header filters through the real pipeline."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)
        self.rules = load_rules()

    def tearDown(self):
        self.directory.cleanup()

    def run_frames(self, frames, rules=None, **options):
        pcap = write_pcap(self.path / "test.pcap", sorted(frames, key=lambda item: item[0]))
        return detect_pcap(pcap, rules or self.rules, **options).alerts

    def test_icmp_rate_below_threshold(self):
        frames = [
            (START + index * 0.0102, icmp_frame(GENERATOR, VICTIM, 8, 7, index, ip_id=index))
            for index in range(99)
        ]
        self.assertEqual(self.run_frames(frames), [])
        frames.append((START + 0.999, icmp_frame(GENERATOR, VICTIM, 8, 7, 99, ip_id=99)))
        self.assertEqual(sids_of(self.run_frames(frames)), [10009])

    def test_icmp_flood_suppressed_then_alerts_again(self):
        flood = scenario_icmp_flood(rate=500, seconds=1.0)
        later = [(timestamp + 30, frame) for timestamp, frame in flood]
        much_later = [(timestamp + 120, frame) for timestamp, frame in flood]
        self.assertEqual(sids_of(self.run_frames(flood + later)), [10009])
        self.assertEqual(sids_of(self.run_frames(flood + later + much_later)), [10009, 10009])

    def test_replies_from_the_victim_do_not_count(self):
        frames = [
            (START + index * 0.001, icmp_frame(VICTIM, GENERATOR, 0, 9, index, ip_id=index))
            for index in range(500)
        ]
        self.assertEqual(self.run_frames(frames), [])

    def test_dns_needs_distinct_queries(self):
        name = "0f3a9c27b1e84d56a1b2c3d4e5f60718.example.com"
        repeated = [
            (START + index * 0.1, udp_frame(GENERATOR, VICTIM, 50000 + index, 53, dns_message(index, name)))
            for index in range(30)
        ]
        self.assertEqual(self.run_frames(repeated), [])
        nine = [
            (START + index, udp_frame(GENERATOR, VICTIM, 50000 + index, 53, dns_message(index, f"{index:02d}{name}")))
            for index in range(9)
        ]
        self.assertEqual(self.run_frames(nine), [])
        ten = nine + [(START + 9, udp_frame(GENERATOR, VICTIM, 50009, 53, dns_message(9, f"09x{name}")))]
        self.assertEqual(sids_of(self.run_frames(ten)), [10010])

    def test_dns_spread_over_many_domains_is_benign(self):
        frames = [
            (START + index, udp_frame(GENERATOR, VICTIM, 50000 + index, 53,
                                      dns_message(index, f"0f3a9c27b1e84d56a1b2c3d4e5f6071{index % 10}.site{index}.com")))
            for index in range(30)
        ]
        self.assertEqual(self.run_frames(frames), [])

    def test_small_scan_is_not_alerted(self):
        ports = list(range(1000, 1019))
        self.assertEqual(self.run_frames(syn_scan_frames(ports, START)), [])
        self.assertEqual(sids_of(self.run_frames(syn_scan_frames(ports + [1019], START))), [10002])

    def test_slow_scan_below_rate(self):
        # 40 ports, one every 0.5 s: never 20 ports within 5 s.
        frames = syn_scan_frames(list(range(2000, 2040)), START, interval=0.5)
        self.assertEqual(self.run_frames(frames), [])

    def test_repeated_scan_is_suppressed(self):
        first = syn_scan_frames(list(range(1, 101)), START)
        second = syn_scan_frames(list(range(101, 201)), START + 60)
        self.assertEqual(sids_of(self.run_frames(first + second)), [10002])

    def test_supersedes_only_on_the_same_request(self):
        conv = conversation(43100, 80, START).handshake()
        conv.send_client(curl_request("/a?id=1%20UNION%20SELECT%201"))
        conv.send_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        conv.send_client(curl_request("/b?id=1%20UNION/**/SELECT%201"))
        alerts = self.run_frames(conv.close().frames)
        self.assertEqual(sids_of(alerts), [10004, 10005])

    def test_http_rules_follow_the_port_variable(self):
        conv = conversation(43101, 9999, START).handshake()
        conv.send_client(curl_request("/x?q=%3Cscript%3E"))
        self.assertEqual(self.run_frames(conv.close().frames), [])

    def test_disabled_and_enabled_rules(self):
        frames = scenario_factory.scenario_benign_icmp()
        self.assertEqual(self.run_frames(frames), [])
        self.rules.set_enabled(10001, True)
        alerts = self.run_frames(frames)
        # One alert per (source, destination) per suppress window of 60 s.
        self.assertEqual(sids_of(alerts), [10001, 10001])
        self.rules.set_enabled(10009, False)
        flood = scenario_icmp_flood(rate=500, seconds=1.0)
        self.assertNotIn(10009, sids_of(self.run_frames(flood)))

    def test_alerts_are_streamed_to_callback(self):
        seen = []
        pipeline = DetectionPipeline(self.rules, on_alert=seen.append)
        pipeline.run_pcap(write_pcap(self.path / "flood.pcap", scenario_icmp_flood(rate=500, seconds=0.5)))
        self.assertEqual(len(seen), 1)  # threshold reached before the end of the capture
        pipeline.finish()
        self.assertEqual(sids_of(seen), [10009])


class CustomRuleTests(unittest.TestCase):
    """Rule types the shipped rule set does not use."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_threshold_on_tcp_flags_and_packet_payload(self):
        (self.path / "custom.yaml").write_text(textwrap.dedent(
            """
            rules:
              - sid: 30001
                name: SYN_FLOOD
                protocol: tcp
                detection: {type: threshold, tcp_flags: S, count: 50, seconds: 1, track: by_dst}
                severity: high
                suppress: 60
              - sid: 30002
                name: SSH_BANNER
                protocol: tcp
                source: {ports: [22]}
                detection: {type: content, buffer: packet_payload, pattern: "SSH-2.0-OpenSSH", nocase: false}
                severity: low
            """
        ), encoding="utf-8")
        rules = load_rules([self.path])
        frames = syn_scan_frames(list(range(1, 60)), START) + scenario_factory.scenario_benign_ssh()
        pcap = write_pcap(self.path / "mixed.pcap", sorted(frames, key=lambda item: item[0]))
        self.assertEqual(sids_of(detect_pcap(pcap, rules).alerts), [30001, 30002])


class CliTests(unittest.TestCase):
    def test_list_rules(self):
        completed = run_cli("--list-rules")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("10 rules from 5 file(s), 9 enabled", completed.stdout)
        self.assertIn("sid=10001 rev=1 ICMP_TRAFFIC [low] icmp/protocol event=packet disabled", completed.stdout)

    def test_invalid_rules_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.yaml"
            bad.write_text("rules:\n  - sid: 1\n    name: BAD\n", encoding="utf-8")
            completed = run_cli("--list-rules", "--rules", bad)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("Invalid rules", completed.stderr)
        self.assertIn("'severity' must be one of", completed.stderr)

    def test_unknown_sid(self):
        completed = run_cli("--list-rules", "--enable", "424242")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("unknown SID 424242", completed.stderr)


class BenignCaptureTests(unittest.TestCase):
    """Real BENIGN captures in data/: zero alerts."""

    def test_real_benign_captures(self):
        rules = load_rules()
        for scenario, (relative, sid) in GROUND_TRUTH.items():
            if sid is not None:
                continue
            pcap = DATA_DIR / relative
            with self.subTest(pcap=relative):
                if not pcap.is_file() or pcap.stat().st_size <= PCAP_GLOBAL_HEADER_BYTES:
                    self.skipTest(f"{relative} has no packets yet")
                text, alerts = report(pcap, f"real/{scenario}", "verbose")
                self.assertEqual(alerts, [], text)


if __name__ == "__main__":
    unittest.main()
