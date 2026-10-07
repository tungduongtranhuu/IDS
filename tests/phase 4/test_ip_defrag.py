import struct
import sys
import unittest
from pathlib import Path

import dpkt


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(WORKSPACE_ROOT / "ids" / "phase 4"))

from ip_defrag import (
    FRAG_BAD_LENGTH,
    FRAG_DUPLICATE,
    FRAG_OVERLAP_CONFLICT,
    FRAG_TABLE_FULL,
    FRAG_TIMEOUT,
    FRAG_TINY_FIRST,
    FRAG_TOO_LARGE,
    FRAG_TOO_MANY,
    IpDefragmenter,
    ipv4_checksum,
    parse_ipv4_frame,
)
from pcap_factory import (
    CLIENT_IP,
    SERVER_IP,
    ethernet,
    fragment_frames,
    ipv4,
    tcp_segment,
    udp_datagram,
)


UDP = udp_datagram(CLIENT_IP, SERVER_IP, 5555, 53, bytes(range(64)))  # 72 bytes


def run(defragmenter, frames, start=0.0):
    outputs = [defragmenter.process(start + index * 0.01, frame) for index, frame in enumerate(frames)]
    return [output for output in outputs if output is not None]


def fragments(pieces, ip_id=99, transport=UDP, protocol=17, vlan=None):
    return fragment_frames(CLIENT_IP, SERVER_IP, protocol, transport, ip_id, pieces, vlan=vlan)


def ip_layer(output):
    return dpkt.ethernet.Ethernet(output.frame).data


class PassThroughTests(unittest.TestCase):
    def test_unfragmented_frame_is_unchanged(self):
        frame = ethernet(ipv4(CLIENT_IP, SERVER_IP, 17, UDP))
        output = IpDefragmenter().process(0, frame, 100, 100)
        self.assertEqual(output.frame, frame)
        self.assertEqual((output.fragment_count, output.capture_length), (0, 100))

    def test_non_ip_frame_is_unchanged(self):
        arp = b"\xff" * 6 + b"\x02" * 6 + struct.pack("!H", 0x0806) + b"\x00" * 28
        self.assertEqual(IpDefragmenter().process(0, arp).frame, arp)

    def test_parse_ignores_ethernet_padding(self):
        frame = ethernet(ipv4(CLIENT_IP, SERVER_IP, 17, UDP)) + b"\x00" * 10
        self.assertEqual(parse_ipv4_frame(frame).payload, UDP)


class ReassemblyTests(unittest.TestCase):
    PIECES = [(0, 24), (24, 24), (48, 24)]

    def assert_rebuilt(self, output, transport=UDP):
        ip = ip_layer(output)
        self.assertEqual(ip.offset, 0)
        self.assertFalse(ip.mf)
        self.assertEqual(bytes(ip.data), transport)
        header = output.frame[14:34]
        self.assertEqual(ipv4_checksum(header), 0)

    def test_in_order_fragments(self):
        defragmenter = IpDefragmenter()
        outputs = run(defragmenter, fragments(self.PIECES))
        self.assertEqual(len(outputs), 1)
        self.assertEqual(outputs[0].fragment_count, 3)
        self.assert_rebuilt(outputs[0])
        self.assertEqual(defragmenter.statistics()["reassembled"], 1)

    def test_reverse_order_fragments(self):
        outputs = run(IpDefragmenter(), list(reversed(fragments(self.PIECES))))
        self.assertEqual(len(outputs), 1)
        self.assert_rebuilt(outputs[0])

    def test_two_datagrams_interleaved(self):
        first = fragments(self.PIECES, ip_id=1)
        second = fragments(self.PIECES, ip_id=2)
        interleaved = [frame for pair in zip(first, second) for frame in pair]
        outputs = run(IpDefragmenter(), interleaved)
        self.assertEqual(len(outputs), 2)

    def test_duplicate_fragment(self):
        frames = fragments(self.PIECES)
        outputs = run(IpDefragmenter(), [frames[0], frames[0], frames[1], frames[2]])
        self.assertIn(FRAG_DUPLICATE, outputs[0].anomalies)
        self.assert_rebuilt(outputs[0])

    def overlap_frames(self):
        return fragments(
            [(0, UDP[:24], True), (16, b"X" * 16, True), (32, UDP[32:], False)]
        )

    def test_overlap_conflict_policy_first(self):
        events = []
        output = run(IpDefragmenter(on_anomaly=events.append), self.overlap_frames())[0]
        data = bytes(ip_layer(output).data)
        self.assertEqual(data[16:24], UDP[16:24])
        self.assertEqual(data[24:32], b"X" * 8)
        self.assertIn(FRAG_OVERLAP_CONFLICT, output.anomalies)
        self.assertEqual(events[0].anomaly, FRAG_OVERLAP_CONFLICT)
        self.assertEqual(events[0].ip_id, 99)

    def test_overlap_conflict_policy_last(self):
        output = run(IpDefragmenter(overlap_policy="last"), self.overlap_frames())[0]
        self.assertEqual(bytes(ip_layer(output).data)[16:32], b"X" * 16)

    def test_tiny_first_fragment(self):
        tcp = tcp_segment(CLIENT_IP, SERVER_IP, 4000, 80, 1, 1, 0x18, b"GET / HTTP/1.1\r\n\r\n")
        output = run(IpDefragmenter(), fragments([(0, 8), (8, len(tcp) - 8)], transport=tcp, protocol=6))[0]
        self.assertIn(FRAG_TINY_FIRST, output.anomalies)
        self.assert_rebuilt(output, tcp)

    def test_bad_fragment_length_never_completes(self):
        defragmenter = IpDefragmenter()
        frames = fragments([(0, UDP[:20], True), (24, UDP[24:], False)])
        self.assertEqual(run(defragmenter, frames), [])
        self.assertEqual(defragmenter.anomaly_counts[FRAG_BAD_LENGTH], 1)
        self.assertEqual(defragmenter.flush(), 1)
        self.assertEqual(defragmenter.anomaly_counts[FRAG_TIMEOUT], 1)

    def test_vlan_tagged_fragments(self):
        output = run(IpDefragmenter(), fragments(self.PIECES, vlan=10))[0]
        self.assertEqual(output.frame[12:14], b"\x81\x00")
        self.assertEqual(bytes(dpkt.ethernet.Ethernet(output.frame).data.data), UDP)


class LimitTests(unittest.TestCase):
    def test_too_large_datagram_is_dropped(self):
        defragmenter = IpDefragmenter()
        self.assertEqual(run(defragmenter, fragments([(65528, b"A" * 16, False)])), [])
        self.assertEqual(defragmenter.anomaly_counts, {FRAG_TOO_LARGE: 1})
        self.assertEqual(defragmenter.datagrams, {})

    def test_incomplete_datagram_times_out(self):
        events = []
        defragmenter = IpDefragmenter(timeout=30, on_anomaly=events.append)
        defragmenter.process(0, fragments([(0, 24)])[0])
        defragmenter.process(31, ethernet(ipv4(CLIENT_IP, SERVER_IP, 17, UDP)))
        self.assertEqual(defragmenter.statistics()["dropped"], 1)
        self.assertEqual(events[0].anomaly, FRAG_TIMEOUT)
        self.assertIn("last fragment missing", events[0].detail)

    def test_flush_reports_missing_bytes(self):
        events = []
        defragmenter = IpDefragmenter(on_anomaly=events.append)
        run(defragmenter, fragments([(0, 24), (48, 24)]))
        defragmenter.flush()
        self.assertIn("missing bytes 24-48", events[0].detail)

    def test_table_full(self):
        defragmenter = IpDefragmenter(max_datagrams=1)
        defragmenter.process(0, fragments([(0, 24)], ip_id=1)[0])
        self.assertIsNone(defragmenter.process(0.1, fragments([(0, 24)], ip_id=2)[0]))
        self.assertEqual(defragmenter.anomaly_counts, {FRAG_TABLE_FULL: 1})
        self.assertEqual(len(defragmenter.datagrams), 1)

    def test_too_many_fragments(self):
        defragmenter = IpDefragmenter(max_fragments=2)
        frames = fragments(ReassemblyTests.PIECES)
        self.assertEqual(run(defragmenter, frames), [])
        self.assertEqual(defragmenter.anomaly_counts, {FRAG_TOO_MANY: 1})

    def test_invalid_arguments(self):
        for arguments in ({"timeout": 0}, {"overlap_policy": "middle"}, {"max_datagrams": 0}):
            with self.subTest(arguments=arguments):
                self.assertRaises(ValueError, IpDefragmenter, **arguments)


if __name__ == "__main__":
    unittest.main()
