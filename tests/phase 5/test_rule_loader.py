"""Phase 5 rule loading: YAML schema, validation errors and SID management."""

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(WORKSPACE_ROOT / "ids" / "phase 5"))

from rule_loader import (
    EVENT_HTTP,
    EVENT_PACKET,
    EVENT_SCAN,
    ContentDetection,
    EndpointMatch,
    RegexDetection,
    RuleError,
    load_rules,
)


VALID_RULE = """
  - sid: {sid}
    name: {name}
    protocol: tcp
    detection: {{type: content, buffer: http_uri, pattern: "union select"}}
    severity: high
"""


class RuleFiles:
    """Write YAML snippets into a temporary rules directory."""

    def __init__(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)

    def write(self, name: str, text: str) -> Path:
        path = self.path / name
        path.write_text(textwrap.dedent(text), encoding="utf-8")
        return path

    def load(self):
        return load_rules([self.path])

    def errors(self) -> str:
        """Load and return every validation message (fails if the rules are valid)."""
        try:
            self.load()
        except RuleError as error:
            return "\n".join(error.errors)
        raise AssertionError("RuleError was not raised")

    def cleanup(self):
        self.directory.cleanup()


class DefaultRulesTests(unittest.TestCase):
    def test_shipped_rules_load(self):
        ruleset = load_rules()
        self.assertEqual(sorted(ruleset.rules), [10001, 10002, 10003, 10004, 10006, 10007, 10008, 10009, 10010])
        self.assertFalse(ruleset.get(10001).enabled)
        self.assertEqual(len(ruleset.enabled_rules()), 8)
        self.assertEqual(ruleset.get(10004).event, EVENT_HTTP)
        self.assertEqual(ruleset.get(10002).event, EVENT_SCAN)
        self.assertEqual(ruleset.get(10009).event, EVENT_PACKET)

    def test_variables_are_expanded(self):
        ruleset = load_rules()
        ports = ruleset.get(10004).destination.ports
        self.assertIn((80, 80), ports)
        self.assertIn((3000, 3000), ports)
        self.assertEqual(ruleset.variables["DNS_PORTS"], [53])

    def test_ground_truth_severities(self):
        ruleset = load_rules()
        expected = {
            10002: "medium", 10003: "high", 10004: "high", 10006: "critical",
            10007: "high", 10008: "medium", 10009: "high", 10010: "high",
        }
        for sid, severity in expected.items():
            self.assertEqual(ruleset.get(sid).severity, severity, sid)

    def test_enable_and_disable(self):
        ruleset = load_rules()
        ruleset.set_enabled(10001, True)
        ruleset.set_enabled(10004, False)
        enabled = {rule.sid for rule in ruleset.enabled_rules()}
        self.assertIn(10001, enabled)
        self.assertNotIn(10004, enabled)
        with self.assertRaises(KeyError):
            ruleset.set_enabled(99999, True)


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.files = RuleFiles()

    def tearDown(self):
        self.files.cleanup()

    def rules(self, body: str, name="test.yaml"):
        return self.files.write(name, "rules:\n" + textwrap.dedent(body))

    def test_minimal_rule_and_defaults(self):
        self.rules(VALID_RULE.format(sid=1, name="A_RULE"))
        rule = self.files.load().get(1)
        self.assertEqual(rule.rev, 1)
        self.assertTrue(rule.enabled)
        self.assertIsInstance(rule.detection, ContentDetection)
        self.assertEqual(rule.detection.patterns, ("union select",))
        self.assertEqual(rule.direction, "any")

    def test_nocase_patterns_are_lowercased(self):
        self.rules(
            """
            - sid: 1
              name: UPPER
              protocol: tcp
              detection: {type: content, buffer: http_uri_raw, pattern: "UNION Select"}
              severity: low
            - sid: 2
              name: EXACT
              protocol: tcp
              detection: {type: content, buffer: http_uri_raw, pattern: "UNION", nocase: false}
              severity: low
            """
        )
        ruleset = self.files.load()
        self.assertEqual(ruleset.get(1).detection.patterns, ("union select",))
        self.assertEqual(ruleset.get(2).detection.patterns, ("UNION",))

    def test_unknown_key_is_reported(self):
        self.rules(
            """
            - sid: 1
              name: TYPO
              protocol: tcp
              detection: {type: content, buffer: http_uri, pattern: x, nocsae: true}
              severity: high
              severty: high
            """
        )
        errors = self.files.errors()
        self.assertIn("unknown key 'nocsae'", errors)
        self.assertIn("unknown key 'severty'", errors)

    def test_every_problem_is_collected(self):
        self.rules(
            """
            - sid: -5
              name: lower_case
              protocol: sctp
              detection: {type: magic}
              severity: urgent
            - sid: 2
              name: BAD_REGEX
              protocol: tcp
              detection: {type: regex, buffer: http_uri, pattern: "(unclosed"}
              severity: high
            """
        )
        errors = self.files.errors()
        for text in ("'sid' must be a positive integer", "'name' must look like", "'protocol' must be one of",
                     "unknown type 'magic'", "'severity' must be one of", "invalid regex"):
            self.assertIn(text, errors)

    def test_duplicate_sid_and_name_across_files(self):
        self.rules(VALID_RULE.format(sid=7, name="FIRST"), "a.yaml")
        self.rules(VALID_RULE.format(sid=7, name="SECOND") + VALID_RULE.format(sid=8, name="FIRST"), "b.yaml")
        errors = self.files.errors()
        self.assertIn("duplicate SID 7 (already in a.yaml)", errors)
        self.assertIn("duplicate name FIRST", errors)

    def test_buffers_must_fit_protocol_and_event(self):
        self.rules(
            """
            - sid: 1
              name: HTTP_ON_UDP
              protocol: udp
              detection: {type: content, buffer: http_uri, pattern: x}
              severity: low
            - sid: 2
              name: UNKNOWN_BUFFER
              protocol: tcp
              detection: {type: content, buffer: http_cookie, pattern: x}
              severity: low
            - sid: 3
              name: MIXED
              protocol: tcp
              detection: {type: content, buffers: [http_uri, packet_payload], pattern: x}
              severity: low
            - sid: 4
              name: BOTH_FORMS
              protocol: tcp
              detection: {type: content, buffer: http_uri, pattern: x, patterns: [y]}
              severity: low
            """
        )
        errors = self.files.errors()
        self.assertIn("http_* buffers need protocol tcp", errors)
        self.assertIn("unknown buffer http_cookie", errors)
        self.assertIn("do not mix http_* and packet buffers", errors)
        self.assertIn("give exactly one of 'pattern' or 'patterns'", errors)

    def test_header_combinations(self):
        self.rules(
            """
            - sid: 1
              name: SCAN_WITH_PORTS
              protocol: tcp
              destination: {ports: [80]}
              detection: {type: scan, technique: half_open, unique_dst_ports: 20, seconds: 5}
              severity: low
            - sid: 2
              name: ICMP_WITH_PORTS
              protocol: icmp
              destination: {ports: [80]}
              detection: {type: protocol}
              severity: low
            - sid: 3
              name: FLAGS_ON_ICMP
              protocol: icmp
              detection: {type: threshold, count: 5, seconds: 1, tcp_flags: S}
              severity: low
            - sid: 4
              name: HTTP_TO_CLIENT
              protocol: tcp
              flow: {direction: to_client}
              detection: {type: content, buffer: http_uri, pattern: x}
              severity: low
            - sid: 5
              name: BAD_PORT
              protocol: tcp
              destination: {ports: ["80-20", 70000, abc], ips: [300.1.1.1]}
              detection: {type: protocol}
              severity: low
            """
        )
        errors = self.files.errors()
        self.assertIn("scan rules match hosts only", errors)
        self.assertIn("ports need protocol tcp or udp", errors)
        self.assertIn("tcp_flags needs protocol tcp", errors)
        self.assertIn("direction to_client never matches", errors)
        self.assertIn("port out of range '80-20'", errors)
        self.assertIn("port out of range '70000'", errors)
        self.assertIn("invalid port 'abc'", errors)
        self.assertIn("invalid IP or CIDR '300.1.1.1'", errors)

    def test_supersedes_references(self):
        self.rules(
            """
            - sid: 1
              name: A
              protocol: tcp
              detection: {type: content, buffer: http_uri, pattern: a}
              severity: low
              supersedes: [2, 99, 1]
            - sid: 2
              name: B
              protocol: tcp
              detection: {type: content, buffer: http_uri, pattern: b}
              severity: low
              supersedes: [1]
            - sid: 3
              name: C
              protocol: icmp
              detection: {type: protocol}
              severity: low
              supersedes: [2]
            """
        )
        errors = self.files.errors()
        self.assertIn("supersedes unknown SID 99", errors)
        self.assertIn("cannot supersede itself", errors)
        self.assertIn("supersede each other", errors)
        self.assertIn("matches another event type", errors)

    def test_variables(self):
        self.files.write("vars.yaml", "vars:\n  WEB: [80, '8000-8080']\n  NET: [10.0.0.0/8]\n")
        self.rules(
            """
            - sid: 1
              name: WITH_VARS
              protocol: tcp
              source: {ips: $NET}
              destination: {ports: [$WEB, 9000]}
              detection: {type: content, buffer: http_uri, pattern: a}
              severity: low
            - sid: 2
              name: MISSING_VAR
              protocol: tcp
              destination: {ports: $NOPE}
              detection: {type: content, buffer: http_uri, pattern: a}
              severity: low
            """
        )
        errors = self.files.errors()
        self.assertIn("undefined variable $NOPE", errors)
        self.files.write("test.yaml", "rules:\n" + textwrap.dedent(
            """
            - sid: 1
              name: WITH_VARS
              protocol: tcp
              source: {ips: $NET}
              destination: {ports: [$WEB, 9000]}
              detection: {type: content, buffer: http_uri, pattern: a}
              severity: low
            """
        ))
        rule = self.files.load().get(1)
        self.assertEqual(rule.destination.ports, ((80, 80), (8000, 8080), (9000, 9000)))
        self.assertTrue(rule.source.matches("10.1.2.3", None))
        self.assertFalse(rule.source.matches("192.168.1.1", None))

    def test_conflicting_variable_definitions(self):
        self.files.write("a.yaml", "vars:\n  PORTS: [80]\n")
        self.files.write("b.yaml", "vars:\n  PORTS: [81]\n")
        self.assertIn("variable PORTS redefined", self.files.errors())

    def test_yaml_syntax_and_layout_errors(self):
        self.files.write("broken.yaml", "rules:\n  - sid: 1\n    name: [unclosed\n")
        self.files.write("list.yaml", "- just a list\n")
        self.files.write("extra.yaml", "rules: []\nsettings: {}\n")
        errors = self.files.errors()
        self.assertIn("YAML syntax error", errors)
        self.assertIn("top level must be a mapping", errors)
        self.assertIn("unknown key 'settings'", errors)

    def test_regex_rules_compile_with_nocase(self):
        self.rules(
            """
            - sid: 1
              name: REGEX
              protocol: tcp
              detection: {type: regex, buffer: http_uri_decoded, patterns: ['union\\s+select']}
              severity: low
            """
        )
        detection = self.files.load().get(1).detection
        self.assertIsInstance(detection, RegexDetection)
        self.assertTrue(detection.compiled[0].search("UNION   SELECT"))

    def test_empty_directory(self):
        with self.assertRaises(RuleError):
            self.files.load()


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.files = RuleFiles()

    def tearDown(self):
        self.files.cleanup()

    def test_tcp_flags_exact_and_plus(self):
        self.files.write(
            "flags.yaml",
            "rules:\n" + textwrap.dedent(
                """
                - sid: 1
                  name: SYN_ONLY
                  protocol: tcp
                  detection: {type: protocol, tcp_flags: S}
                  severity: low
                - sid: 2
                  name: SYN_ANY
                  protocol: tcp
                  detection: {type: protocol, tcp_flags: "S+"}
                  severity: low
                """
            ),
        )
        ruleset = self.files.load()
        exact = ruleset.get(1).detection.packet_filter.tcp_flags
        plus = ruleset.get(2).detection.packet_filter.tcp_flags
        self.assertTrue(exact.matches(0x02))
        self.assertFalse(exact.matches(0x12))
        self.assertTrue(plus.matches(0x12))
        self.assertFalse(plus.matches(0x10))
        self.assertFalse(plus.matches(None))

    def test_endpoint_match(self):
        endpoint = EndpointMatch(ports=((80, 80), (8000, 8080)))
        self.assertTrue(endpoint.matches("1.2.3.4", 8042))
        self.assertFalse(endpoint.matches("1.2.3.4", 443))
        self.assertFalse(endpoint.matches("1.2.3.4", None))
        self.assertTrue(EndpointMatch().matches(None, None))


if __name__ == "__main__":
    unittest.main()
