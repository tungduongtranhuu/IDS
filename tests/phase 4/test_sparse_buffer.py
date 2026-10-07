import sys
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(WORKSPACE_ROOT / "ids" / "phase 4"))

from sparse_buffer import SparseBuffer


class SparseBufferTests(unittest.TestCase):
    def test_write_tracks_ranges_and_gaps(self):
        buffer = SparseBuffer()
        buffer.write(0, b"abc")
        buffer.write(6, b"ghi")
        self.assertEqual(buffer.ranges, [[0, 3], [6, 9]])
        self.assertEqual(buffer.gaps(0, 9), [(3, 6)])
        self.assertEqual(buffer.contiguous_end(0), 3)

        buffer.write(3, b"def")
        self.assertEqual(buffer.ranges, [[0, 9]])
        self.assertEqual(bytes(buffer.data), b"abcdefghi")

    def test_overlap_first_keeps_existing_bytes(self):
        buffer = SparseBuffer()
        buffer.write(0, b"AAAA")
        result = buffer.write(2, b"BBBB", "first")
        self.assertEqual(bytes(buffer.data), b"AAAABB")
        self.assertEqual((result.new_bytes, result.overlap_bytes, result.conflict_bytes), (2, 2, 2))

    def test_overlap_last_overwrites(self):
        buffer = SparseBuffer()
        buffer.write(0, b"AAAA")
        buffer.write(2, b"BBBB", "last")
        self.assertEqual(bytes(buffer.data), b"AABBBB")

    def test_identical_overlap_is_not_a_conflict(self):
        buffer = SparseBuffer()
        buffer.write(0, b"hello")
        result = buffer.write(1, b"ell")
        self.assertEqual((result.overlap_bytes, result.conflict_bytes, result.new_bytes), (3, 0, 0))

    def test_pop_front_shifts_ranges(self):
        buffer = SparseBuffer()
        buffer.write(0, b"abc")
        buffer.write(5, b"xy")
        self.assertEqual(buffer.pop_front(3), b"abc")
        self.assertEqual(buffer.ranges, [[2, 4]])
        self.assertEqual(buffer.chunks(), [(2, b"xy")])

    def test_zero_bytes_count_as_data(self):
        buffer = SparseBuffer()
        buffer.write(0, b"\x00\x00")
        self.assertEqual(buffer.contiguous_end(0), 2)
        self.assertEqual(buffer.covered_bytes, 2)

    def test_invalid_arguments(self):
        buffer = SparseBuffer()
        self.assertRaises(ValueError, buffer.write, -1, b"x")
        self.assertRaises(ValueError, buffer.write, 0, b"x", "middle")


if __name__ == "__main__":
    unittest.main()
