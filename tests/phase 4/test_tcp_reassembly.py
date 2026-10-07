import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
for directory in ("phase 2", "phase 3", "phase 4"):
    sys.path.insert(0, str(WORKSPACE_ROOT / "ids" / directory))

from flow_manager import FlowManager
from tcp_reassembly import (
    TCP_GAP,
    TCP_OLD_DATA,
    TCP_OUT_OF_ORDER,
    TCP_OUT_OF_WINDOW,
    TCP_OVERLAP_CONFLICT,
    TCP_RETRANSMISSION,
    TCP_RST_PAYLOAD,
    TCP_STREAM_TRUNCATED,
    StreamDirection,
    TcpReassembler,
    seq_offset,
)


SYN = 0x02
RST = 0x04
PSH_ACK = 0x18
SYN_ACK = 0x12
ACK = 0x10


def fake_flow(key="flow", continuation=False):
    return SimpleNamespace(key=key, protocol="TCP", is_continuation=continuation, termination_reason=None)


def segment(seq, payload=b"", flags=PSH_ACK, **extra):
    return SimpleNamespace(tcp_seq=seq, tcp_flags=flags, payload=payload, **extra)


class SequenceTests(unittest.TestCase):
    def test_seq_offset_handles_wraparound(self):
        self.assertEqual(seq_offset(5, (1 << 32) - 5), 10)
        self.assertEqual(seq_offset((1 << 32) - 5, 5), -10)
        self.assertEqual(seq_offset(1000, 1000), 0)


class StreamDirectionTests(unittest.TestCase):
    def direction(self, base=1000):
        return StreamDirection(base_seq=base)

    def test_in_order_segments(self):
        direction = self.direction()
        self.assertEqual(direction.add_segment(1000, b"GET "), b"GET ")
        self.assertEqual(direction.add_segment(1004, b"/"), b"/")
        self.assertEqual(bytes(direction.data), b"GET /")

    def test_out_of_order_union_select(self):
        """Exercise from doc_for_phase.md: 'UNI', 'ON SE', 'LECT' out of order."""
        direction = self.direction()
        self.assertEqual(direction.add_segment(1000, b"UNI"), b"UNI")
        self.assertEqual(direction.add_segment(1008, b"LECT"), b"")
        self.assertEqual(direction.add_segment(1003, b"ON SE"), b"ON SELECT")
        self.assertEqual(bytes(direction.data), b"UNION SELECT")
        self.assertEqual(direction.out_of_order_segments, 1)
        self.assertEqual(direction.anomalies, {TCP_OUT_OF_ORDER: 1})

    def test_identical_retransmission(self):
        direction = self.direction()
        direction.add_segment(1000, b"hello")
        self.assertEqual(direction.add_segment(1000, b"hello"), b"")
        self.assertEqual(direction.retransmitted_bytes, 5)
        self.assertEqual(direction.anomalies, {TCP_RETRANSMISSION: 1})

    def test_retransmission_with_different_bytes_is_conflict(self):
        direction = self.direction()
        direction.add_segment(1000, b"hello")
        direction.add_segment(1000, b"HELLO")
        self.assertEqual(bytes(direction.data), b"hello")
        self.assertEqual(direction.conflict_bytes, 5)
        self.assertIn(TCP_OVERLAP_CONFLICT, direction.anomalies)

    def test_partial_overlap_appends_only_new_bytes(self):
        direction = self.direction()
        direction.add_segment(1000, b"ABCDEF")
        self.assertEqual(direction.add_segment(1004, b"EFGH"), b"GH")
        self.assertEqual(bytes(direction.data), b"ABCDEFGH")

    def pending_overlap(self, policy):
        direction = self.direction()
        direction.add_segment(1005, b"decoy", policy)
        direction.add_segment(1005, b"union", policy)
        direction.add_segment(1000, b"1 or ", policy)
        return direction

    def test_pending_overlap_policy_first(self):
        direction = self.pending_overlap("first")
        self.assertEqual(bytes(direction.data), b"1 or decoy")
        self.assertIn(TCP_OVERLAP_CONFLICT, direction.anomalies)

    def test_pending_overlap_policy_last(self):
        direction = self.pending_overlap("last")
        self.assertEqual(bytes(direction.data), b"1 or union")
        self.assertIn(TCP_OVERLAP_CONFLICT, direction.anomalies)

    def test_old_data_before_stream_start(self):
        direction = self.direction()
        self.assertEqual(direction.add_segment(990, b"xxxxx"), b"")
        self.assertEqual(direction.add_segment(995, b"xxxxxHELLO"), b"HELLO")
        self.assertEqual(direction.anomalies[TCP_OLD_DATA], 2)
        self.assertEqual(direction.dropped_bytes, 10)

    def test_segment_far_ahead_is_out_of_window(self):
        direction = self.direction()
        direction.add_segment(1200, b"far", max_window_bytes=100)
        self.assertEqual(direction.anomalies, {TCP_OUT_OF_WINDOW: 1})
        self.assertEqual(direction.pending_bytes, 0)

    def test_gap_at_finish_keeps_unassembled_chunk(self):
        direction = self.direction()
        direction.add_segment(1000, b"head")
        direction.add_segment(1010, b"tail")
        direction.finish()
        self.assertEqual(direction.unassembled, [(10, b"tail")])
        self.assertIn(TCP_GAP, direction.anomalies)

    def test_stream_depth_limit(self):
        direction = self.direction()
        direction.add_segment(1000, b"ABCDEF", max_stream_bytes=4)
        self.assertEqual(bytes(direction.data), b"ABCD")
        self.assertEqual(direction.next_offset, 6)
        self.assertTrue(direction.truncated)
        self.assertIn(TCP_STREAM_TRUNCATED, direction.anomalies)

    def test_sequence_wraparound(self):
        direction = self.direction(base=(1 << 32) - 3)
        direction.add_segment((1 << 32) - 3, b"ABC")
        direction.add_segment(3, b"GHI")
        direction.add_segment(0, b"DEF")
        self.assertEqual(bytes(direction.data), b"ABCDEFGHI")

    def test_midstream_first_segment_defines_base(self):
        direction = StreamDirection()
        direction.add_segment(777, b"abc")
        self.assertEqual(direction.base_seq, 777)
        self.assertEqual(direction.next_seq, 780)


class ReassemblerTests(unittest.TestCase):
    def test_syn_sets_base_and_data_follows(self):
        chunks = []
        reassembler = TcpReassembler(on_data=lambda stream, forward, chunk: chunks.append((forward, chunk)))
        flow = fake_flow()
        reassembler.process(flow, segment(999, flags=SYN), True)
        reassembler.process(flow, segment(4999, flags=SYN_ACK), False)
        reassembler.process(flow, segment(1000, b"GET"), True)
        reassembler.process(flow, segment(5000, b"HTTP"), False)
        stream = reassembler.streams["flow"]
        self.assertEqual((stream.client.base_seq, stream.server.base_seq), (1000, 5000))
        self.assertEqual(chunks, [(True, b"GET"), (False, b"HTTP")])

    def test_on_data_order(self):
        chunks = []
        reassembler = TcpReassembler(on_data=lambda stream, forward, chunk: chunks.append(chunk))
        flow = fake_flow()
        reassembler.process(flow, segment(999, flags=SYN), True)
        reassembler.process(flow, segment(1003, b" /"), True)
        reassembler.process(flow, segment(1000, b"GET"), True)
        self.assertEqual(chunks, [b"GET /"])

    def test_syn_with_data(self):
        reassembler = TcpReassembler()
        flow = fake_flow()
        reassembler.process(flow, segment(999, b"HI", flags=SYN), True)
        stream = reassembler.streams["flow"]
        self.assertEqual(stream.client.base_seq, 1000)
        self.assertEqual(bytes(stream.client.data), b"HI")

    def test_non_tcp_and_incomplete_packets_ignored(self):
        reassembler = TcpReassembler()
        reassembler.process(SimpleNamespace(key="u", protocol="UDP"), segment(1, b"x"), True)
        reassembler.process(fake_flow(), SimpleNamespace(tcp_seq=None, tcp_flags=None, payload=b"x"), True)
        self.assertEqual(reassembler.streams, {})

    def test_rst_payload_is_ignored(self):
        reassembler = TcpReassembler()
        flow = fake_flow()
        reassembler.process(flow, segment(1000, b"evil", flags=RST), True)
        stream = reassembler.streams["flow"]
        self.assertEqual(bytes(stream.client.data), b"")
        self.assertIn(TCP_RST_PAYLOAD, stream.anomalies)
        self.assertTrue(stream.suspicious)

    def test_defrag_anomalies_are_attached_to_stream(self):
        reassembler = TcpReassembler()
        flow = fake_flow()
        reassembler.process(flow, segment(1000, b"x", defrag_anomalies=("FRAG_TINY_FIRST",)), True)
        self.assertTrue(reassembler.streams["flow"].suspicious)

    def test_close_flow_finishes_stream(self):
        finished = []
        reassembler = TcpReassembler(on_stream_end=finished.append)
        flow = fake_flow()
        reassembler.process(flow, segment(1000, b"data"), True)
        stream = reassembler.close_flow(flow)
        self.assertEqual(finished, [stream])
        self.assertTrue(stream.closed)
        self.assertEqual(reassembler.streams, {})
        self.assertIsNone(reassembler.close_flow(fake_flow("other")))

    def test_replaced_flow_without_close_finishes_old_stream(self):
        finished = []
        reassembler = TcpReassembler(on_stream_end=finished.append)
        old_flow, new_flow = fake_flow(), fake_flow()
        reassembler.process(old_flow, segment(1000, b"a"), True)
        reassembler.process(new_flow, segment(1000, b"b"), True)
        self.assertEqual(len(finished), 1)
        self.assertIs(finished[0].flow, old_flow)

    def test_invalid_arguments(self):
        self.assertRaises(ValueError, TcpReassembler, overlap_policy="middle")
        self.assertRaises(ValueError, TcpReassembler, max_window_bytes=0)


class FlowManagerIntegrationTests(unittest.TestCase):
    CLIENT = ("10.0.0.1", 40000)
    SERVER = ("10.0.0.2", 80)

    def packet(self, timestamp, from_client, seq, flags, payload=b""):
        src, dst = (self.CLIENT, self.SERVER) if from_client else (self.SERVER, self.CLIENT)
        return SimpleNamespace(
            timestamp=timestamp,
            src_ip=src[0],
            src_port=src[1],
            dst_ip=dst[0],
            dst_port=dst[1],
            ip_protocol="TCP",
            capture_length=60,
            payload=payload,
            tcp_flags=flags,
            tcp_seq=seq,
        )

    def test_hooks_and_active_timeout_continuation(self):
        finished = []
        reassembler = TcpReassembler(on_stream_end=finished.append)
        manager = FlowManager(
            active_timeout=10,
            on_packet=reassembler.process,
            on_flow_end=reassembler.close_flow,
        )
        manager.add_packet(self.packet(0, True, 999, SYN))
        manager.add_packet(self.packet(0.1, False, 4999, SYN_ACK))
        manager.add_packet(self.packet(0.2, True, 1000, ACK))
        manager.add_packet(self.packet(1, True, 1000, PSH_ACK, b"AAAA"))
        # Split by the active timeout, and the next segments arrive out of order.
        manager.add_packet(self.packet(11, True, 1008, PSH_ACK, b"CCCC"))
        manager.add_packet(self.packet(11.1, True, 1004, PSH_ACK, b"BBBB"))
        manager.close_all()

        self.assertEqual(len(finished), 2)
        first, second = finished
        self.assertEqual(bytes(first.client.data), b"AAAA")
        self.assertEqual(first.flow.termination_reason, "ACTIVE_TIMEOUT")
        self.assertTrue(second.flow.is_continuation)
        self.assertEqual(bytes(second.client.data), b"BBBBCCCC")
        self.assertNotIn(TCP_OLD_DATA, second.anomalies)


if __name__ == "__main__":
    unittest.main()
