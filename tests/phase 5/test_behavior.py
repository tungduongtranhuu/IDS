"""Phase 5 behavioral building blocks: sliding windows, scan episodes, DNS features."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(WORKSPACE_ROOT / "ids" / "phase 5"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from behavior import (
    TECHNIQUE_CONNECT,
    TECHNIQUE_HALF_OPEN,
    TECHNIQUE_OTHER,
    TECHNIQUE_SERVICE,
    ScanEpisode,
    ScanTracker,
    SlidingWindow,
    dns_query_features,
    shannon_entropy,
)
from scenario_factory import dns_message


class SlidingWindowTests(unittest.TestCase):
    def test_threshold_inside_window(self):
        window = SlidingWindow(count=3, seconds=1.0)
        self.assertIsNone(window.add("a", 0.0))
        self.assertIsNone(window.add("a", 0.5))
        events = window.add("a", 0.9, "third")
        self.assertEqual([timestamp for timestamp, _item in events], [0.0, 0.5, 0.9])
        self.assertEqual(events[-1][1], "third")

    def test_events_spread_too_wide_do_not_count(self):
        window = SlidingWindow(count=3, seconds=1.0)
        for timestamp in (0.0, 0.6, 1.2, 1.8):
            self.assertIsNone(window.add("a", timestamp))
        self.assertIsNotNone(window.add("a", 1.9))

    def test_keys_are_independent_and_reset(self):
        window = SlidingWindow(count=2, seconds=1.0)
        window.add("a", 0.0)
        self.assertIsNone(window.add("b", 0.1))
        self.assertIsNotNone(window.add("a", 0.2))
        window.reset("a")
        self.assertIsNone(window.add("a", 0.3))

    def test_contains_and_expire(self):
        window = SlidingWindow(count=5, seconds=1.0)
        window.add("a", 0.0, "x")
        self.assertTrue(window.contains("a", "x"))
        self.assertFalse(window.contains("a", "y"))
        self.assertEqual(window.expire(5.0), 1)
        self.assertFalse(window.contains("a", "x"))

    def test_memory_is_bounded(self):
        window = SlidingWindow(count=2, seconds=100.0, max_keys=3)
        for index in range(10):
            window.add(index, float(index))
        self.assertLessEqual(len(window.events), 3)
        self.assertIn(9, window.events)


class ScanEpisodeTests(unittest.TestCase):
    def episode(self, **flags_by_port) -> ScanEpisode:
        episode = ScanEpisode("10.0.0.1", "10.0.0.2", 0.0, 0.0)
        for port, flags in flags_by_port.items():
            episode.probe(int(port.strip("p")), 0.0, syn="syn" in flags)
            probe = episode.ports[int(port.strip("p"))]
            probe.completed = "completed" in flags
            probe.client_payload = "payload" in flags
        return episode

    def test_technique_is_most_specific(self):
        self.assertEqual(self.episode(p1="syn", p2="syn").technique, TECHNIQUE_HALF_OPEN)
        self.assertEqual(self.episode(p1="syn", p2="syn completed").technique, TECHNIQUE_CONNECT)
        self.assertEqual(self.episode(p1="syn completed", p2="syn completed payload").technique, TECHNIQUE_SERVICE)
        self.assertEqual(self.episode(p1="", p2="").technique, TECHNIQUE_OTHER)

    def test_peak_ports_in_window(self):
        episode = ScanEpisode("a", "b", 0.0, 0.0)
        for port, timestamp in enumerate((0.0, 1.0, 2.0, 10.0, 10.5, 11.0, 11.5), start=1):
            episode.probe(port, timestamp, syn=True)
        self.assertEqual(episode.peak_ports(5.0), 4)
        self.assertEqual(episode.peak_ports(0.4), 1)
        self.assertEqual(episode.peak_ports(100.0), 7)

    def test_repeated_probe_keeps_first_time(self):
        episode = ScanEpisode("a", "b", 0.0, 0.0)
        episode.probe(80, 1.0, syn=False)
        episode.probe(80, 9.0, syn=True)
        self.assertEqual(episode.ports[80].first_seen, 1.0)
        self.assertTrue(episode.ports[80].syn)
        self.assertEqual(episode.connections, 2)


def fake_flow(client_port, server_port, fwd_packets=1, handshake=False):
    return SimpleNamespace(
        protocol="TCP",
        client=("10.0.0.1", client_port),
        server=("10.0.0.2", server_port),
        fwd_packets=fwd_packets,
        handshake_completed=handshake,
    )


def fake_packet(timestamp, flags=0x02, payload=b""):
    return SimpleNamespace(timestamp=timestamp, tcp_flags=flags, payload=payload)


class ScanTrackerTests(unittest.TestCase):
    def test_episode_closes_after_idle_timeout(self):
        tracker = ScanTracker(idle_timeout=10.0, max_duration=60.0)
        for port in range(1, 6):
            tracker.observe(fake_flow(40000, port), fake_packet(port * 0.1), True)
        self.assertEqual(tracker.expire(5.0), [])
        closed = tracker.expire(10.6)
        self.assertEqual(len(closed), 1)
        self.assertEqual(len(closed[0].ports), 5)
        self.assertEqual(closed[0].technique, TECHNIQUE_HALF_OPEN)

    def test_long_episode_is_cut_at_max_duration(self):
        tracker = ScanTracker(idle_timeout=10.0, max_duration=30.0)
        for second in range(0, 40, 2):
            tracker.observe(fake_flow(40000, 1000 + second), fake_packet(float(second)), True)
            closed = tracker.expire(float(second))
            if closed:
                self.assertEqual(second, 30)
                break
        else:
            self.fail("episode was never cut")

    def test_handshake_and_payload_update_the_port(self):
        tracker = ScanTracker()
        flow = fake_flow(40000, 80)
        tracker.observe(flow, fake_packet(0.0), True)
        flow.fwd_packets, flow.handshake_completed = 2, True
        tracker.observe(flow, fake_packet(0.1, 0x10), True)
        flow.fwd_packets = 3
        tracker.observe(flow, fake_packet(0.2, 0x18, b"GET / HTTP/1.0\r\n\r\n"), True)
        episode = tracker.flush()[0]
        self.assertTrue(episode.ports[80].completed)
        self.assertTrue(episode.ports[80].client_payload)
        self.assertEqual(episode.technique, TECHNIQUE_SERVICE)

    def test_server_packets_and_old_flows_are_ignored(self):
        tracker = ScanTracker()
        tracker.observe(fake_flow(40000, 80), fake_packet(0.0), False)
        tracker.observe(fake_flow(40000, 81, fwd_packets=5), fake_packet(0.0), True)
        self.assertEqual(tracker.flush(), [])


class DnsFeatureTests(unittest.TestCase):
    def test_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)
        self.assertGreater(shannon_entropy("0f3a9c27b1e84d56"), 3.5)

    def test_query_features(self):
        name = "0f3a9c27b1e84d56a1b2c3d4e5f60718.example.com"
        features = dns_query_features(dns_message(1, name))
        self.assertEqual(features.qname, name)
        self.assertEqual(features.base_domain, "example.com")
        self.assertEqual(features.subdomain_length, 32)
        self.assertEqual(features.longest_label, 32)
        self.assertGreater(features.entropy, 3.0)

    def test_plain_domain_has_no_subdomain(self):
        features = dns_query_features(dns_message(1, "Example.COM"))
        self.assertEqual(features.qname, "example.com")
        self.assertEqual(features.subdomain, "")
        self.assertEqual(features.entropy, 0.0)

    def test_responses_and_garbage_are_ignored(self):
        self.assertIsNone(dns_query_features(dns_message(1, "example.com", response=True)))
        self.assertIsNone(dns_query_features(b"\x01\x02garbage"))
        self.assertIsNone(dns_query_features(b""))


if __name__ == "__main__":
    unittest.main()
