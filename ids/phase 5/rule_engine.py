#!/usr/bin/env python3

"""Phase 5 rule engine: match YAML rules on the Phase 4 pipeline and raise alerts.

    raw frame -> IpDefragmenter -> PacketDecoder -> FlowManager -> TcpReassembler -> HttpStreamParser
                                                        | on_packet                        | on_http_request
                                                        v                                  v
                                   DetectionEngine: packet rules, scan episodes      HTTP rules (content / regex
                                   (protocol, threshold, dns_tunnel, scan)            on raw / decoded / normalized)
                                                        |                                  |
                                                        +---------------> Alert <----------+
                                                                    (report + alerts.jsonl)

Three kinds of events are matched:
    packet  every decoded packet (after defragmentation)
    http    every complete HTTP request of a reassembled TCP stream
    scan    a closed scan episode (one source probing one target)
"""

import argparse
import json
import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import dpkt


PHASE_FIVE_DIR = Path(__file__).resolve().parent
for phase_dir in (
    PHASE_FIVE_DIR.parent / "phase 2",
    PHASE_FIVE_DIR.parent / "phase 3",
    PHASE_FIVE_DIR.parent / "phase 4",
):
    if str(phase_dir) not in sys.path:
        sys.path.insert(0, str(phase_dir))

from anti_evasion import AntiEvasionPipeline
from behavior import (
    DEFAULT_SCAN_IDLE_TIMEOUT,
    DEFAULT_SCAN_MAX_DURATION,
    ScanEpisode,
    ScanTracker,
    SlidingWindow,
    dns_query_features,
)
from http_normalizer import HttpRequest
from rule_loader import (
    DEFAULT_RULES_DIR,
    EVENT_HTTP,
    EVENT_PACKET,
    EVENT_SCAN,
    ContentDetection,
    DnsTunnelDetection,
    ProtocolDetection,
    RegexDetection,
    Rule,
    RuleError,
    RuleSet,
    ThresholdDetection,
    load_rules,
)
from sparse_buffer import OVERLAP_FIRST, OVERLAP_POLICIES
from tcp_reassembly import SUSPICIOUS_TCP_ANOMALIES, TcpStream


LOGGER = logging.getLogger(__name__)
OUTPUT_MODES = ("quiet", "normal", "verbose", "debug")
SEVERITY_LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
EVIDENCE_TEXT_LIMIT = 512
MAX_INSPECTED_BYTES = 64 * 1024
DEFAULT_SWEEP_INTERVAL = 1.0
HOUSEKEEPING_INTERVAL = 60.0

Match = tuple[Rule, dict[str, Any]]


def _clip(text: str, limit: int = EVIDENCE_TEXT_LIMIT) -> str:
    return text if len(text) <= limit else text[:limit] + f"... (+{len(text) - limit} chars)"


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="microseconds")


@dataclass
class Alert:
    """One rule match. Phase 8 turns this into a full ECS event."""

    timestamp: float
    sid: int
    rev: int
    name: str
    description: str
    severity: str
    category: str
    detection_type: str
    event: str
    protocol: str
    src_ip: Optional[str]
    src_port: Optional[int]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()

    @classmethod
    def from_rule(cls, rule: Rule, timestamp: float, protocol, src, dst, evidence) -> "Alert":
        return cls(
            timestamp=timestamp,
            sid=rule.sid,
            rev=rule.rev,
            name=rule.name,
            description=rule.description,
            severity=rule.severity,
            category=rule.category,
            detection_type=rule.detection.type,
            event=rule.event,
            protocol=protocol,
            src_ip=src[0],
            src_port=src[1],
            dst_ip=dst[0],
            dst_port=dst[1],
            evidence=evidence,
            tags=rule.tags,
        )

    def summary(self) -> str:
        def endpoint(ip, port):
            return f"{ip}:{port}" if port is not None else str(ip)

        return (
            f"[{self.severity}] sid={self.sid} rev={self.rev} {self.name} {self.protocol} "
            f"{endpoint(self.src_ip, self.src_port)} -> {endpoint(self.dst_ip, self.dst_port)} "
            f"at {_iso(self.timestamp)}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "@timestamp": _iso(self.timestamp),
            "timestamp": self.timestamp,
            "rule": {
                "id": self.sid,
                "rev": self.rev,
                "name": self.name,
                "description": self.description,
                "category": self.category,
                "tags": list(self.tags),
            },
            "severity": self.severity,
            "severity_level": SEVERITY_LEVELS[self.severity],
            "detection": {"type": self.detection_type, "event": self.event},
            "network": {"protocol": (self.protocol or "").lower()},
            "source": {"ip": self.src_ip, "port": self.src_port},
            "destination": {"ip": self.dst_ip, "port": self.dst_port},
            "evidence": self.evidence,
        }


def http_buffers(request: HttpRequest) -> dict[str, str]:
    """Every inspectable view of one request (Phase 4 keeps raw and normalized apart)."""
    headers = "\n".join(f"{name}: {value}" for name, value in request.headers)
    return {
        "http_method": request.method,
        "http_uri_raw": request.uri_raw,
        "http_uri_decoded": request.uri_decoded,
        "http_uri": request.uri_normalized,
        "http_path": request.path_normalized,
        "http_header": headers,
        "http_host": request.header("Host") or "",
        "http_user_agent": request.header("User-Agent") or "",
        "http_body_decoded": request.body_decoded,
        "http_body": request.body_normalized,
    }


class ContentMatcher:
    """Which content patterns occur in which buffers.

    One pass per (buffer, pattern) with `in`. Phase 6 replaces the inside of
    search() with an Aho-Corasick automaton; the interface stays the same.
    """

    def __init__(self, rules: list[Rule]):
        self.entries: dict[tuple[str, bool], list[tuple[str, int]]] = {}
        for rule in rules:
            detection = rule.detection
            if not isinstance(detection, ContentDetection):
                continue
            for buffer in detection.buffers:
                for pattern in detection.patterns:
                    self.entries.setdefault((buffer, detection.nocase), []).append((pattern, rule.sid))

    @property
    def buffers(self) -> set[str]:
        return {buffer for buffer, _nocase in self.entries}

    def search(self, buffers: dict[str, str]) -> dict[int, list[tuple[str, str]]]:
        """Return {sid: [(buffer, pattern), ...]} for every pattern found."""
        hits: dict[int, list[tuple[str, str]]] = {}
        for (buffer, nocase), entries in self.entries.items():
            text = buffers.get(buffer)
            if not text:
                continue
            text = text[:MAX_INSPECTED_BYTES]
            haystack = text.lower() if nocase else text
            for pattern, sid in entries:
                if pattern in haystack:
                    hits.setdefault(sid, []).append((buffer, pattern))
        return hits


def match_payload_rule(rule: Rule, buffers: dict[str, str], hits) -> Optional[dict[str, Any]]:
    """Evaluate a content or regex rule on prepared buffers."""
    detection = rule.detection
    if isinstance(detection, ContentDetection):
        found = hits.get(rule.sid, [])
        if not found:
            return None
        if detection.match_all and {pattern for _buffer, pattern in found} != set(detection.patterns):
            return None
        return {
            "matches": [
                {"buffer": buffer, "pattern": pattern, "value": _clip(buffers.get(buffer, ""))}
                for buffer, pattern in found
            ]
        }
    if isinstance(detection, RegexDetection):
        for buffer in detection.buffers:
            text = (buffers.get(buffer) or "")[:MAX_INSPECTED_BYTES]
            for pattern, compiled in zip(detection.patterns, detection.compiled):
                found = compiled.search(text)
                if found:
                    return {
                        "matches": [
                            {
                                "buffer": buffer,
                                "pattern": pattern,
                                "matched": _clip(found.group(0), 200),
                                "value": _clip(text),
                            }
                        ]
                    }
    return None


def resolve_supersedes(matches: list[Match]) -> list[Match]:
    """On one event, drop rules superseded by a more specific rule that also matched."""
    matched = {rule.sid for rule, _evidence in matches}
    resolved = []
    for rule, evidence in matches:
        dropped = sorted(sid for sid in rule.supersedes if sid in matched)
        if dropped:
            evidence = {**evidence, "superseded_sids": dropped}
        resolved.append((rule, evidence))
    superseded = {sid for rule, _evidence in matches for sid in rule.supersedes}
    return [(rule, evidence) for rule, evidence in resolved if rule.sid not in superseded]


@dataclass
class EngineStatistics:
    packets: int = 0
    http_requests: int = 0
    dns_queries: int = 0
    scan_episodes: int = 0
    suppressed: int = 0
    alerts: int = 0
    alerts_by_sid: dict[int, int] = field(default_factory=dict)
    alerts_by_severity: dict[str, int] = field(default_factory=dict)


class DetectionEngine:
    """Evaluate enabled rules on packets, HTTP requests and scan episodes."""

    def __init__(
        self,
        ruleset: RuleSet,
        on_alert: Optional[Callable[[Alert], None]] = None,
        on_scan_episode: Optional[Callable[[ScanEpisode], None]] = None,
        scan_idle_timeout: float = DEFAULT_SCAN_IDLE_TIMEOUT,
        scan_max_duration: float = DEFAULT_SCAN_MAX_DURATION,
        sweep_interval: float = DEFAULT_SWEEP_INTERVAL,
        keep_alerts: bool = True,
    ):
        self.ruleset = ruleset
        self.on_alert = on_alert
        self.on_scan_episode = on_scan_episode
        self.sweep_interval = sweep_interval
        self.keep_alerts = keep_alerts
        self.alerts: list[Alert] = []
        self.stats = EngineStatistics()

        enabled = ruleset.enabled_rules()
        self.packet_rules: dict[str, list[Rule]] = {}
        for rule in enabled:
            if rule.event == EVENT_PACKET:
                self.packet_rules.setdefault(rule.protocol.upper(), []).append(rule)
        self.http_rules = [rule for rule in enabled if rule.event == EVENT_HTTP]
        self.scan_rules = [rule for rule in enabled if rule.event == EVENT_SCAN]
        self.http_content = ContentMatcher(self.http_rules)
        self.packet_content = ContentMatcher(
            [rule for rules in self.packet_rules.values() for rule in rules]
        )

        self.windows: dict[int, SlidingWindow] = {}
        for rules in self.packet_rules.values():
            for rule in rules:
                detection = rule.detection
                if isinstance(detection, (ThresholdDetection, DnsTunnelDetection)):
                    self.windows[rule.sid] = SlidingWindow(detection.count, detection.seconds)
        self.scans = ScanTracker(scan_idle_timeout, scan_max_duration) if self.scan_rules else None

        self._suppressed_until: dict[tuple[int, Any], float] = {}
        self.clock: Optional[float] = None
        self._last_sweep: Optional[float] = None
        self._last_housekeeping: Optional[float] = None

    # ----------------------------------------------------------------- hooks
    def on_packet(self, flow, packet, is_forward: bool) -> None:
        """AntiEvasionPipeline on_packet hook."""
        timestamp = packet.timestamp
        self._advance(timestamp)
        self.stats.packets += 1
        if self.scans is not None:
            self.scans.observe(flow, packet, is_forward)

        rules = self.packet_rules.get(flow.protocol, []) + self.packet_rules.get("IP", [])
        if not rules:
            return
        src = (packet.src_ip, packet.src_port)
        dst = (packet.dst_ip, packet.dst_port)
        buffers = None
        hits: dict = {}
        matches: list[Match] = []
        for rule in rules:
            if not rule.direction_matches(is_forward) or not rule.endpoints_match(*src, *dst):
                continue
            detection = rule.detection
            evidence = None
            if isinstance(detection, ProtocolDetection):
                if detection.packet_filter.matches(packet):
                    evidence = {"icmp_type": packet.icmp_type} if flow.protocol == "ICMP" else {}
            elif isinstance(detection, ThresholdDetection):
                evidence = self._threshold(rule, detection, packet, src, dst)
            elif isinstance(detection, DnsTunnelDetection):
                evidence = self._dns_tunnel(rule, detection, packet)
            else:
                if buffers is None:
                    payload = bytes(packet.payload or b"")[:MAX_INSPECTED_BYTES]
                    buffers = {"packet_payload": payload.decode("latin-1")}
                    hits = self.packet_content.search(buffers)
                evidence = match_payload_rule(rule, buffers, hits)
            if evidence is not None:
                matches.append((rule, evidence))
        if matches:
            self._emit(matches, timestamp, flow.protocol, src, dst, default_key=(src[0], dst[0]))

    def on_http_request(self, stream: TcpStream, request: HttpRequest) -> None:
        """AntiEvasionPipeline on_http_request hook (client -> server only)."""
        self.stats.http_requests += 1
        if not self.http_rules:
            return
        flow = stream.flow
        client, server = flow.client, flow.server
        buffers = http_buffers(request)
        hits = self.http_content.search(buffers)
        matches = []
        for rule in self.http_rules:
            if not rule.endpoints_match(*client, *server):
                continue
            evidence = match_payload_rule(rule, buffers, hits)
            if evidence is not None:
                matches.append((rule, evidence))
        if not matches:
            return
        context = {
            "http_method": request.method,
            "uri_raw": _clip(request.uri_raw),
            "uri_decoded": _clip(request.uri_decoded),
            "uri_normalized": _clip(request.uri_normalized),
            "http_host": request.header("Host"),
            "user_agent": request.header("User-Agent"),
            "request_anomalies": list(request.anomalies),
            "stream_anomalies": sorted(name for name in stream.anomalies if name in SUSPICIOUS_TCP_ANOMALIES),
            "stream_offset": request.offset,
        }
        matches = [(rule, {**context, **evidence}) for rule, evidence in matches]
        self._emit(matches, flow.last_seen, "TCP", client, server, default_key=(client[0], server[0]))

    def finish(self) -> None:
        """End of capture: classify the scan episodes still open."""
        if self.scans is not None:
            for episode in self.scans.flush():
                self._scan_episode(episode)

    # ------------------------------------------------------------- detectors
    def _threshold(self, rule: Rule, detection: ThresholdDetection, packet, src, dst):
        if not detection.packet_filter.matches(packet):
            return None
        key = {"by_src": src[0], "by_dst": dst[0], "by_pair": (src[0], dst[0])}[detection.track]
        window = self.windows[rule.sid]
        events = window.add(key, packet.timestamp)
        if events is None:
            return None
        window.reset(key)
        return {
            "_key": key,
            "track": detection.track,
            "packets": len(events),
            "window_seconds": detection.seconds,
            "first_seen": events[0][0],
            "last_seen": events[-1][0],
        }

    def _dns_tunnel(self, rule: Rule, detection: DnsTunnelDetection, packet):
        if packet.dst_port != 53 or not packet.payload:
            return None
        features = dns_query_features(bytes(packet.payload))
        if features is None:
            return None
        self.stats.dns_queries += 1
        if features.subdomain_length < detection.min_subdomain_length or features.entropy < detection.min_entropy:
            return None
        key = (packet.src_ip, features.base_domain)
        window = self.windows[rule.sid]
        if window.contains(key, features):
            return None
        events = window.add(key, packet.timestamp, features)
        if events is None:
            return None
        window.reset(key)
        queries = [item for _timestamp, item in events]
        return {
            "_key": key,
            "base_domain": features.base_domain,
            "suspicious_queries": len(queries),
            "window_seconds": detection.seconds,
            "max_entropy": max(query.entropy for query in queries),
            "max_subdomain_length": max(query.subdomain_length for query in queries),
            "sample_queries": [query.qname for query in queries[:5]],
            "first_seen": events[0][0],
            "last_seen": events[-1][0],
        }

    def _scan_episode(self, episode: ScanEpisode) -> None:
        self.stats.scan_episodes += 1
        if self.on_scan_episode is not None:
            self.on_scan_episode(episode)
        technique = episode.technique
        matches = []
        for rule in self.scan_rules:
            detection = rule.detection
            if detection.technique != technique:
                continue
            if not rule.endpoints_match(episode.src_ip, None, episode.dst_ip, None):
                continue
            if episode.peak_ports(detection.seconds) < detection.unique_dst_ports:
                continue
            matches.append((rule, episode.evidence(detection.seconds)))
        if matches:
            self._emit(
                matches,
                episode.last_activity,
                "TCP",
                (episode.src_ip, None),
                (episode.dst_ip, None),
                default_key=(episode.src_ip, episode.dst_ip),
            )

    # ---------------------------------------------------------------- alerts
    def _emit(self, matches: list[Match], timestamp: float, protocol, src, dst, default_key) -> None:
        for rule, evidence in resolve_supersedes(matches):
            key = (rule.sid, evidence.pop("_key", default_key))
            if self._suppressed_until.get(key, float("-inf")) > timestamp:
                self.stats.suppressed += 1
                continue
            if rule.suppress:
                self._suppressed_until[key] = timestamp + rule.suppress
            alert = Alert.from_rule(rule, timestamp, protocol, src, dst, evidence)
            self.stats.alerts += 1
            self.stats.alerts_by_sid[rule.sid] = self.stats.alerts_by_sid.get(rule.sid, 0) + 1
            self.stats.alerts_by_severity[rule.severity] = self.stats.alerts_by_severity.get(rule.severity, 0) + 1
            if self.keep_alerts:
                self.alerts.append(alert)
            if self.on_alert is not None:
                self.on_alert(alert)

    def _advance(self, timestamp: float) -> None:
        """Packet-time clock: close idle scan episodes and forget stale state."""
        if self.clock is None or timestamp > self.clock:
            self.clock = timestamp
        if self._last_sweep is None:
            self._last_sweep = self._last_housekeeping = self.clock
            return
        if self.clock - self._last_sweep >= self.sweep_interval:
            self._last_sweep = self.clock
            if self.scans is not None:
                for episode in self.scans.expire(self.clock):
                    self._scan_episode(episode)
        if self.clock - self._last_housekeeping >= HOUSEKEEPING_INTERVAL:
            self._last_housekeeping = self.clock
            for window in self.windows.values():
                window.expire(self.clock)
            self._suppressed_until = {
                key: until for key, until in self._suppressed_until.items() if until > self.clock
            }


class DetectionPipeline:
    """Phase 4 AntiEvasionPipeline with a DetectionEngine on its hooks."""

    def __init__(
        self,
        ruleset: RuleSet,
        on_alert: Optional[Callable[[Alert], None]] = None,
        on_http_request: Optional[Callable[[TcpStream, HttpRequest], None]] = None,
        on_scan_episode: Optional[Callable[[ScanEpisode], None]] = None,
        flow_timeout: Optional[float] = None,
        overlap_policy: str = OVERLAP_FIRST,
        scan_idle_timeout: float = DEFAULT_SCAN_IDLE_TIMEOUT,
    ):
        self.engine = DetectionEngine(
            ruleset,
            on_alert=on_alert,
            on_scan_episode=on_scan_episode,
            scan_idle_timeout=scan_idle_timeout,
        )
        self.on_http_request = on_http_request
        self.pipeline = AntiEvasionPipeline(
            flow_timeout=flow_timeout,
            overlap_policy=overlap_policy,
            on_packet=self.engine.on_packet,
            on_http_request=self._on_http_request,
        )

    @property
    def alerts(self) -> list[Alert]:
        return self.engine.alerts

    def _on_http_request(self, stream: TcpStream, request: HttpRequest) -> None:
        if self.on_http_request is not None:
            self.on_http_request(stream, request)
        self.engine.on_http_request(stream, request)

    def process_frame(self, timestamp, raw_frame, capture_length=None, wire_length=None):
        return self.pipeline.process_frame(timestamp, raw_frame, capture_length, wire_length)

    def run_pcap(self, filename, packet_limit: Optional[int] = None) -> None:
        self.pipeline.run_pcap(filename, packet_limit)

    def finish(self) -> None:
        self.pipeline.finish()
        self.engine.finish()


def detect_pcap(filename, ruleset: Optional[RuleSet] = None, **options) -> DetectionPipeline:
    """Run every stage on a PCAP and return the finished pipeline (alerts in .alerts)."""
    pipeline = DetectionPipeline(ruleset if ruleset is not None else load_rules(), **options)
    pipeline.run_pcap(filename)
    pipeline.finish()
    return pipeline


# ---------------------------------------------------------------------- CLI
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


def _alert_reporter(output_mode: str, alerts_file) -> Callable[[Alert], None]:
    counter = 0

    def report(alert: Alert) -> None:
        nonlocal counter
        counter += 1
        if alerts_file is not None:
            alerts_file.write(json.dumps(alert.to_dict(), ensure_ascii=False, default=str) + "\n")
            alerts_file.flush()
        LOGGER.warning("ALERT #%d %s", counter, alert.summary())
        if output_mode in ("verbose", "debug"):
            for name, value in alert.evidence.items():
                if name == "matches":
                    for match in value:
                        LOGGER.info("    match: %s", match)
                else:
                    LOGGER.info("    %s: %s", name, value)

    return report


def _debug_request(stream: TcpStream, request: HttpRequest) -> None:
    LOGGER.debug("HTTP request %s: %s %s", stream.flow.summary(), request.method, request.uri_raw)
    for name, value in http_buffers(request).items():
        if value:
            LOGGER.debug("    %s = %s", name, _clip(value, 200))


def _debug_episode(episode: ScanEpisode) -> None:
    LOGGER.debug(
        "Scan episode %s -> %s: technique=%s ports=%d connections=%d completed=%d duration=%.3fs",
        episode.src_ip,
        episode.dst_ip,
        episode.technique,
        len(episode.ports),
        episode.connections,
        episode.count("completed"),
        episode.duration,
    )


def log_ruleset(ruleset: RuleSet, output_mode: str) -> None:
    LOGGER.info(
        "Rules: files=%d loaded=%d enabled=%d by_type=%s",
        len(ruleset.files),
        len(ruleset),
        len(ruleset.enabled_rules()),
        ruleset.counts(),
    )
    if output_mode in ("verbose", "debug"):
        for rule in ruleset:
            LOGGER.info("  %s", rule.summary())


def analyze_pcap_to_file(
    filename,
    result_file,
    ruleset: RuleSet,
    alerts_path=None,
    packet_limit: Optional[int] = None,
    output_mode: str = "normal",
    flow_timeout: Optional[float] = None,
    overlap_policy: str = OVERLAP_FIRST,
    scan_idle_timeout: float = DEFAULT_SCAN_IDLE_TIMEOUT,
) -> DetectionPipeline:
    """Run detection on a PCAP, write a text report and (optionally) alerts as JSON lines."""
    root_logger, previous_level, handler = _configure_result_logging(result_file, output_mode)
    alerts_file = None
    try:
        if alerts_path:
            Path(alerts_path).parent.mkdir(parents=True, exist_ok=True)
            alerts_file = open(alerts_path, "w", encoding="utf-8")
        LOGGER.info("CUSTOM IDS - PHASE 5 RULE ENGINE (DETECTION)")
        LOGGER.info("PCAP file: %s", filename)
        LOGGER.info("Output mode: %s", output_mode)
        LOGGER.info("Overlap policy: %s", overlap_policy)
        log_ruleset(ruleset, output_mode)

        debug = output_mode == "debug"
        pipeline = DetectionPipeline(
            ruleset,
            on_alert=_alert_reporter(output_mode, alerts_file),
            on_http_request=_debug_request if debug else None,
            on_scan_episode=_debug_episode if debug else None,
            flow_timeout=flow_timeout,
            overlap_policy=overlap_policy,
            scan_idle_timeout=scan_idle_timeout,
        )
        try:
            pipeline.run_pcap(filename, packet_limit)
        except FileNotFoundError:
            LOGGER.error("PCAP file not found: %s", filename)
        except (ValueError, dpkt.dpkt.Error) as error:
            LOGGER.error("Could not read PCAP: %s", error)
        pipeline.finish()

        stats = pipeline.engine.stats
        LOGGER.info(
            "Detection: packets=%d http_requests=%d dns_queries=%d scan_episodes=%d "
            "alerts=%d suppressed=%d",
            stats.packets,
            stats.http_requests,
            stats.dns_queries,
            stats.scan_episodes,
            stats.alerts,
            stats.suppressed,
        )
        LOGGER.info("Alerts by SID: %s", dict(sorted(stats.alerts_by_sid.items())))
        LOGGER.info("Alerts by severity: %s", stats.alerts_by_severity)
        stages = pipeline.pipeline
        flows = stages.flow_manager.statistics()
        LOGGER.info("Flows: flows=%d packets=%d end_reasons=%s", flows["flows"], flows["packets"], stages.flow_manager.termination_counts)
        LOGGER.info("TCP reassembly: streams=%d anomalies=%s", stages.reassembler.statistics()["streams"], stages.reassembler.anomaly_counts)
        LOGGER.info("IP defrag: anomalies=%s", stages.defragmenter.anomaly_counts)
        if alerts_path:
            LOGGER.info("Alerts written to: %s", alerts_path)
        return pipeline
    finally:
        if alerts_file is not None:
            alerts_file.close()
        handler.flush()
        root_logger.removeHandler(handler)
        handler.close()
        root_logger.setLevel(previous_level)


def build_ruleset(rule_paths, enable=(), disable=()) -> RuleSet:
    ruleset = load_rules(rule_paths or (DEFAULT_RULES_DIR,))
    for sid in enable:
        ruleset.set_enabled(sid, True)
    for sid in disable:
        ruleset.set_enabled(sid, False)
    return ruleset


def get_arguments(arguments=None):
    parser = argparse.ArgumentParser(description="Phase 5 rule engine (detection)")
    parser.add_argument("pcap", nargs="?", help="PCAP file to analyze")
    parser.add_argument("--rules", action="append", help=f"Rule file or directory (repeatable, default: {DEFAULT_RULES_DIR})")
    parser.add_argument("--enable", action="append", type=int, default=[], metavar="SID", help="Enable a disabled rule")
    parser.add_argument("--disable", action="append", type=int, default=[], metavar="SID", help="Disable a rule")
    parser.add_argument("--list-rules", action="store_true", help="Validate rules, list them and exit")
    parser.add_argument("-n", "--limit", type=int, default=None)
    parser.add_argument("--timeout", type=float, default=None, help="Single flow idle timeout")
    parser.add_argument("--overlap-policy", choices=OVERLAP_POLICIES, default=OVERLAP_FIRST)
    parser.add_argument("--scan-idle", type=float, default=DEFAULT_SCAN_IDLE_TIMEOUT, help="Seconds of silence that end a scan episode")
    parser.add_argument("--mode", choices=OUTPUT_MODES, default="normal")
    parser.add_argument("--result", default="rule_engine_result.txt")
    parser.add_argument("--alerts", default="alerts.jsonl", help="JSON lines alert file ('' to disable)")
    args = parser.parse_args(arguments)
    if not args.list_rules and not args.pcap:
        parser.error("a PCAP file is required (or use --list-rules)")
    return args


def main(arguments=None) -> int:
    args = get_arguments(arguments)
    try:
        ruleset = build_ruleset(args.rules, args.enable, args.disable)
    except RuleError as error:
        print(f"Invalid rules ({len(error.errors)} problem(s)):", file=sys.stderr)
        for message in error.errors:
            print(f"  - {message}", file=sys.stderr)
        return 2
    except KeyError as error:
        print(error.args[0], file=sys.stderr)
        return 2

    if args.list_rules:
        print(f"{len(ruleset)} rules from {len(ruleset.files)} file(s), {len(ruleset.enabled_rules())} enabled")
        for rule in ruleset:
            print(f"  {rule.summary()}")
        return 0

    analyze_pcap_to_file(
        filename=args.pcap,
        result_file=args.result,
        ruleset=ruleset,
        alerts_path=args.alerts or None,
        packet_limit=args.limit,
        output_mode=args.mode,
        flow_timeout=args.timeout,
        overlap_policy=args.overlap_policy,
        scan_idle_timeout=args.scan_idle,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
