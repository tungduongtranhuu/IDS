"""Offset-addressed byte buffer shared by IP defragmentation and TCP reassembly."""

from dataclasses import dataclass


OVERLAP_FIRST = "first"
OVERLAP_LAST = "last"
OVERLAP_POLICIES = (OVERLAP_FIRST, OVERLAP_LAST)


@dataclass
class WriteResult:
    """What happened when a piece of data was written into the buffer."""

    new_bytes: int = 0
    overlap_bytes: int = 0
    conflict_bytes: int = 0


class SparseBuffer:
    """Byte buffer with holes.

    Data is written at an offset. The buffer remembers which ranges really
    hold data (`ranges`, sorted and merged, each [start, end)), so it can tell
    missing bytes from bytes that happen to be zero, and detect overlaps.
    """

    def __init__(self):
        self.data = bytearray()
        self.ranges: list[list[int]] = []

    def write(self, offset: int, payload: bytes, policy: str = OVERLAP_FIRST) -> WriteResult:
        """Store payload at offset and report overlaps with existing data.

        policy "first": bytes already in the buffer win (new data only fills holes).
        policy "last": new bytes overwrite existing ones.
        """
        if offset < 0:
            raise ValueError("offset must not be negative")
        if policy not in OVERLAP_POLICIES:
            raise ValueError(f"unknown overlap policy: {policy}")
        end = offset + len(payload)
        result = WriteResult()
        if not payload:
            return result
        if end > len(self.data):
            self.data.extend(bytes(end - len(self.data)))

        for start, stop in self.ranges:
            low, high = max(start, offset), min(stop, end)
            if low < high:
                result.overlap_bytes += high - low
                old = self.data[low:high]
                new = payload[low - offset:high - offset]
                if old != new:
                    result.conflict_bytes += sum(
                        1 for old_byte, new_byte in zip(old, new) if old_byte != new_byte
                    )
        result.new_bytes = len(payload) - result.overlap_bytes

        if policy == OVERLAP_LAST:
            self.data[offset:end] = payload
        else:
            for low, high in self.gaps(offset, end):
                self.data[low:high] = payload[low - offset:high - offset]
        self._add_range(offset, end)
        return result

    def gaps(self, start: int, end: int) -> list[tuple[int, int]]:
        """Return the sub-ranges of [start, end) that hold no data."""
        holes = []
        cursor = start
        for range_start, range_end in self.ranges:
            if range_end <= cursor:
                continue
            if range_start >= end:
                break
            if range_start > cursor:
                holes.append((cursor, range_start))
            cursor = max(cursor, range_end)
            if cursor >= end:
                break
        if cursor < end:
            holes.append((cursor, end))
        return holes

    def _add_range(self, start: int, end: int) -> None:
        merged = []
        placed = False
        for range_start, range_end in self.ranges:
            if range_end < start:
                merged.append([range_start, range_end])
            elif range_start > end:
                if not placed:
                    merged.append([start, end])
                    placed = True
                merged.append([range_start, range_end])
            else:
                start = min(start, range_start)
                end = max(end, range_end)
        if not placed:
            merged.append([start, end])
        self.ranges = merged

    def contiguous_end(self, start: int = 0) -> int:
        """Return the end of the data run that covers `start` (start if none)."""
        for range_start, range_end in self.ranges:
            if range_start <= start < range_end:
                return range_end
        return start

    def pop_front(self, count: int) -> bytes:
        """Remove and return the first `count` bytes, shifting offsets down."""
        if count <= 0:
            return b""
        chunk = bytes(self.data[:count])
        del self.data[:count]
        shifted = []
        for range_start, range_end in self.ranges:
            range_start, range_end = range_start - count, range_end - count
            if range_end > 0:
                shifted.append([max(range_start, 0), range_end])
        self.ranges = shifted
        return chunk

    @property
    def covered_bytes(self) -> int:
        return sum(range_end - range_start for range_start, range_end in self.ranges)

    @property
    def is_empty(self) -> bool:
        return not self.ranges

    def chunks(self) -> list[tuple[int, bytes]]:
        """Return every stored data run as (offset, bytes)."""
        return [
            (range_start, bytes(self.data[range_start:range_end]))
            for range_start, range_end in self.ranges
        ]
