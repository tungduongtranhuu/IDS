#!/usr/bin/env python3

"""Phase 4 anti-evasion pipeline and PCAP analysis CLI.

    raw frame -> IpDefragmenter -> PacketDecoder -> FlowManager
                                                      | on_packet
                                                      v
                                               TcpReassembler --on_data--> HttpStreamParser
                                                      | on_stream_end            (normalized
                                                      v                           requests)
                                                 report / Phase 5+
"""

import argparse
import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import dpkt


PHASE_FOUR_DIR = Path(__file__).resolve().parent
for phase_dir in (PHASE_FOUR_DIR.parent / "phase 2", PHASE_FOUR_DIR.parent / "phase 3"):
    if str(phase_dir) not in sys.path:
        sys.path.insert(0, str(phase_dir))

from flow_manager import DEFAULT_ACTIVE_TIMEOUT, Flow, FlowManager
from http_normalizer import HttpRequest, HttpStreamParser
from ip_defrag import DEFAULT_FRAGMENT_TIMEOUT, DefragEvent, IpDefragmenter
from packet_decoder import Packet, PacketDecoder
from packet_decoder.decoder import read_pcap_packets
from sparse_buffer import OVERLAP_FIRST, OVERLAP_POLICIES
from tcp_reassembly import DEFAULT_MAX_STREAM_BYTES, TcpReassembler, TcpStream


LOGGER = logging.getLogger(__name__)
OUTPUT_MODES = ("quiet", "normal", "verbose", "debug")
HTTP_CONTEXT_KEY = "http"
PREVIEW_BYTES = 2048


@dataclass
class PipelineStatistics:
    http_requests: int = 0
    http_anomaly_counts: dict[str, int] = field(default_factory=dict)


class AntiEvasionPipeline:
    """Wire Phase 2, 3 and 4 components together for one capture."""

    def __init__(
        self,
        flow_timeout: Optional[float] = None,
        active_timeout: float = DEFAULT_ACTIVE_TIMEOUT,
        fragment_timeout: float = DEFAULT_FRAGMENT_TIMEOUT,
        overlap_policy: str = OVERLAP_FIRST,
        max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
        on_defrag_event: Optional[Callable[[DefragEvent], None]] = None,
        on_stream_end: Optional[Callable[[TcpStream], None]] = None,
        on_packet: Optional[Callable[[Flow, Packet, bool], None]] = None,
        on_http_request: Optional[Callable[[TcpStream, HttpRequest], None]] = None,
    ):
        """on_packet(flow, packet, is_forward) runs after reassembly saw the packet;
        on_http_request(stream, request) runs as soon as a request is complete."""
        self.on_stream_end = on_stream_end
        self.on_packet = on_packet
        self.on_http_request = on_http_request
        self.stats = PipelineStatistics()
        self.defragmenter = IpDefragmenter(
            timeout=fragment_timeout,
            overlap_policy=overlap_policy,
            on_anomaly=on_defrag_event,
        )
        self.decoder = PacketDecoder(output_mode="quiet", keep_packets=False)
        self.reassembler = TcpReassembler(
            overlap_policy=overlap_policy,
            max_stream_bytes=max_stream_bytes,
            on_data=self._on_stream_data,
            on_stream_end=self._on_stream_end,
        )
        self.flow_manager = FlowManager(
            flow_timeout=flow_timeout,
            active_timeout=active_timeout,
            on_packet=self._on_packet,
            on_flow_end=self.reassembler.close_flow,
        )

    def process_frame(self, timestamp, raw_frame, capture_length=None, wire_length=None):
        """Push one captured frame through every stage. Returns the decoded Packet or None."""
        self.decoder.total_packets += 1
        output = self.defragmenter.process(timestamp, raw_frame, capture_length, wire_length)
        if output is None:
            return None
        packet = self.decoder.decode_ethernet(
            output.frame,
            timestamp=output.timestamp,
            capture_length=output.capture_length,
            wire_length=output.wire_length,
        )
        if packet is None:
            return None
        packet.reassembled_fragments = output.fragment_count
        packet.defrag_anomalies = output.anomalies
        self.flow_manager.add_packet(packet)
        return packet

    def run_pcap(self, filename, packet_limit: Optional[int] = None) -> None:
        with open(filename, "rb") as file:
            for count, (timestamp, raw, capture_length, wire_length) in enumerate(
                read_pcap_packets(file), start=1
            ):
                self.process_frame(timestamp, raw, capture_length, wire_length)
                if packet_limit is not None and count >= packet_limit:
                    break

    def finish(self) -> None:
        """End of capture: drop incomplete fragments, close flows and streams."""
        self.defragmenter.flush()
        self.flow_manager.close_all()
        self.reassembler.close_all()

    def _on_packet(self, flow: Flow, packet: Packet, is_forward: bool) -> None:
        self.reassembler.process(flow, packet, is_forward)
        if self.on_packet is not None:
            self.on_packet(flow, packet, is_forward)

    def _on_stream_data(self, stream: TcpStream, is_forward: bool, chunk: bytes) -> None:
        if not is_forward:
            return
        parser = stream.context.get(HTTP_CONTEXT_KEY)
        if parser is None:
            parser = HttpStreamParser()
            stream.context[HTTP_CONTEXT_KEY] = parser
        self._handle_requests(stream, parser.feed(chunk))

    def _on_stream_end(self, stream: TcpStream) -> None:
        parser = stream.context.get(HTTP_CONTEXT_KEY)
        if parser is not None:
            self._handle_requests(stream, parser.finish())
        if self.on_stream_end is not None:
            self.on_stream_end(stream)

    def _handle_requests(self, stream: TcpStream, requests: list[HttpRequest]) -> None:
        for request in requests:
            self.stats.http_requests += 1
            for anomaly in request.anomalies:
                counts = self.stats.http_anomaly_counts
                counts[anomaly] = counts.get(anomaly, 0) + 1
            if self.on_http_request is not None:
                self.on_http_request(stream, request)


def stream_requests(stream: TcpStream) -> list[HttpRequest]:
    parser = stream.context.get(HTTP_CONTEXT_KEY)
    return parser.requests if parser is not None else []


def preview(data: bytes, limit: int = PREVIEW_BYTES) -> str:
    """Readable one-line view of bytes: printable ASCII kept, rest escaped."""
    text = repr(bytes(data[:limit]))[2:-1]
    return text + (f" ... (+{len(data) - limit} bytes)" if len(data) > limit else "")


def _log_request(index: int, request: HttpRequest, output_mode: str) -> None:
    LOGGER.info("  HTTP request #%d (stream offset %d): %s %s %s", index, request.offset, request.method, request.uri_raw, request.version)
    LOGGER.info("    uri_raw        : %s", request.uri_raw)
    LOGGER.info("    uri_decoded    : %s", request.uri_decoded)
    LOGGER.info("    uri_normalized : %s", request.uri_normalized)
    if request.body:
        LOGGER.info("    body_normalized: %s", request.body_normalized[:PREVIEW_BYTES])
    LOGGER.info("    decode_rounds  : %d", request.decode_rounds)
    LOGGER.info("    anomalies      : %s", ", ".join(request.anomalies) or "-")
    if output_mode == "debug":
        for name, value in request.headers:
            LOGGER.debug("    header %s: %s", name, value)


def _stream_reporter(output_mode: str) -> Callable[[TcpStream], None]:
    counter = 0

    def report(stream: TcpStream) -> None:
        nonlocal counter
        counter += 1
        requests = stream_requests(stream)
        request_anomalies = any(request.anomalies for request in requests)
        interesting = stream.suspicious or request_anomalies
        if output_mode == "quiet" or (output_mode == "normal" and not interesting):
            return

        flag = " [SUSPICIOUS]" if interesting else ""
        LOGGER.info("Stream #%d%s: %s", counter, flag, stream.flow.summary())
        LOGGER.info("  client->server: %s", stream.client.summary())
        LOGGER.info("  server->client: %s", stream.server.summary())
        for index, request in enumerate(requests, start=1):
            _log_request(index, request, output_mode)
        if output_mode == "debug":
            LOGGER.debug("  client data: %s", preview(stream.client.data))
            LOGGER.debug("  server data: %s", preview(stream.server.data))
            for name, direction in (("client", stream.client), ("server", stream.server)):
                for offset, chunk in direction.unassembled:
                    LOGGER.debug("  %s unassembled @%d: %s", name, offset, preview(chunk))

    return report


def _configure_result_logging(result_file, output_mode):
    levels = {
        "quiet": logging.ERROR,
        "normal": logging.INFO,
        "verbose": logging.INFO,
        "debug": logging.DEBUG,
    }
    result_path = Path(result_file)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(result_path, mode="w", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root_logger = logging.getLogger()
    previous_level = root_logger.level
    root_logger.setLevel(levels[output_mode])
    root_logger.addHandler(handler)
    return root_logger, previous_level, handler


def analyze_pcap_to_file(
    filename,
    result_file,
    packet_limit: Optional[int] = None,
    output_mode: str = "normal",
    flow_timeout: Optional[float] = None,
    overlap_policy: str = OVERLAP_FIRST,
) -> AntiEvasionPipeline:
    """Run the anti-evasion pipeline on a PCAP and write a text report."""
    root_logger, previous_level, handler = _configure_result_logging(result_file, output_mode)
    try:
        LOGGER.info("CUSTOM IDS - PHASE 4 ANTI-EVASION (IP DEFRAG + TCP REASSEMBLY + NORMALIZATION)")
        LOGGER.info("PCAP file: %s", filename)
        LOGGER.info("Output mode: %s", output_mode)
        LOGGER.info("Overlap policy: %s", overlap_policy)

        def log_defrag_event(event: DefragEvent) -> None:
            LOGGER.warning("IP defrag anomaly: %s", event.summary())

        pipeline = AntiEvasionPipeline(
            flow_timeout=flow_timeout,
            overlap_policy=overlap_policy,
            on_defrag_event=log_defrag_event,
            on_stream_end=_stream_reporter(output_mode),
        )
        try:
            pipeline.run_pcap(filename, packet_limit)
        except FileNotFoundError:
            LOGGER.error("PCAP file not found: %s", filename)
        except (ValueError, dpkt.dpkt.Error) as error:
            LOGGER.error("Could not read PCAP: %s", error)
        pipeline.finish()

        defrag = pipeline.defragmenter.statistics()
        LOGGER.info(
            "IP defrag: frames=%d fragments=%d reassembled=%d dropped=%d anomalies=%s",
            defrag["frames"],
            defrag["fragments"],
            defrag["reassembled"],
            defrag["dropped"],
            pipeline.defragmenter.anomaly_counts,
        )
        pipeline.decoder.print_statistics()
        flows = pipeline.flow_manager.statistics()
        LOGGER.info(
            "Flows: flows=%d packets=%d bytes=%d end_reasons=%s",
            flows["flows"],
            flows["packets"],
            flows["bytes"],
            pipeline.flow_manager.termination_counts,
        )
        reassembly = pipeline.reassembler.statistics()
        LOGGER.info(
            "TCP reassembly: streams=%d bytes_assembled=%d anomalies=%s",
            reassembly["streams"],
            reassembly["bytes_assembled"],
            pipeline.reassembler.anomaly_counts,
        )
        LOGGER.info(
            "HTTP normalization: requests=%d anomalies=%s",
            pipeline.stats.http_requests,
            pipeline.stats.http_anomaly_counts,
        )
        return pipeline
    finally:
        handler.flush()
        root_logger.removeHandler(handler)
        handler.close()
        root_logger.setLevel(previous_level)


def get_arguments(arguments=None):
    parser = argparse.ArgumentParser(description="Phase 4 anti-evasion pipeline")
    parser.add_argument("pcap", help="PCAP file to analyze")
    parser.add_argument("-n", "--limit", type=int, default=None)
    parser.add_argument("--timeout", type=float, default=None, help="Single flow idle timeout")
    parser.add_argument("--overlap-policy", choices=OVERLAP_POLICIES, default=OVERLAP_FIRST)
    parser.add_argument("--mode", choices=OUTPUT_MODES, default="normal")
    parser.add_argument("--result", default="anti_evasion_result.txt")
    return parser.parse_args(arguments)


def main(arguments=None):
    args = get_arguments(arguments)
    analyze_pcap_to_file(
        filename=args.pcap,
        result_file=args.result,
        packet_limit=args.limit,
        output_mode=args.mode,
        flow_timeout=args.timeout,
        overlap_policy=args.overlap_policy,
    )


if __name__ == "__main__":
    main()
