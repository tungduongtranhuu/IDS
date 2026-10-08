"""Phase 5 rule loader: YAML parsing, schema validation and SID management.

A rule file is a YAML mapping with two optional keys:

    vars:                         # shared by every loaded file
      HTTP_PORTS: [80, 3000, 8080]
    rules:
      - sid: 10004
        name: SQL_INJECTION_UNION_SELECT
        protocol: tcp
        destination: {ports: $HTTP_PORTS}
        detection: {type: content, buffer: http_uri, pattern: "union select"}
        severity: high

Every rule is checked before the engine starts: unknown keys (typos such as
`nocsae`), wrong types, unknown buffers, duplicate SIDs, invalid regexes...
All problems are collected and raised together in one RuleError.
"""

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

import yaml


DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"
RULE_FILE_SUFFIXES = (".yaml", ".yml")

SEVERITIES = ("low", "medium", "high", "critical")
PROTOCOLS = ("tcp", "udp", "icmp", "ip")
DIRECTIONS = ("any", "to_server", "to_client")
TRACKS = ("by_src", "by_dst", "by_pair")
SCAN_TECHNIQUES = ("half_open", "connect", "service")

# Where a rule is evaluated.
EVENT_PACKET = "packet"
EVENT_HTTP = "http"
EVENT_SCAN = "scan"

HTTP_BUFFERS = frozenset(
    {
        "http_method",
        "http_uri_raw",
        "http_uri_decoded",
        "http_uri",
        "http_path",
        "http_header",
        "http_host",
        "http_user_agent",
        "http_body_decoded",
        "http_body",
    }
)
PACKET_BUFFERS = frozenset({"packet_payload"})

TCP_FLAG_LETTERS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80}

_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_VARIABLE = re.compile(r"^\$([A-Z][A-Z0-9_]*)$")
_PORT_RANGE = re.compile(r"^(\d+)-(\d+)$")

RULE_KEYS = frozenset(
    {
        "sid", "rev", "name", "description", "category", "severity", "enabled",
        "protocol", "source", "destination", "flow", "detection", "suppress",
        "supersedes", "tags",
    }
)
ENDPOINT_KEYS = frozenset({"ips", "ports"})
FLOW_KEYS = frozenset({"direction"})
PACKET_FILTER_KEYS = frozenset({"tcp_flags", "icmp_type"})
DETECTION_KEYS = {
    "protocol": frozenset({"type"}) | PACKET_FILTER_KEYS,
    "content": frozenset({"type", "buffer", "buffers", "pattern", "patterns", "nocase", "match"}),
    "regex": frozenset({"type", "buffer", "buffers", "pattern", "patterns", "nocase"}),
    "threshold": frozenset({"type", "count", "seconds", "track"}) | PACKET_FILTER_KEYS,
    "scan": frozenset({"type", "technique", "unique_dst_ports", "seconds"}),
    "dns_tunnel": frozenset(
        {"type", "min_subdomain_length", "min_entropy", "count", "seconds"}
    ),
}


class RuleError(ValueError):
    """One or more rules are invalid. `errors` lists every problem found."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("\n".join(self.errors))


@dataclass(frozen=True)
class TcpFlagsFilter:
    """Snort-style flags: "S" = exactly SYN, "S+" = SYN set, other bits ignored."""

    mask: int
    exact: bool
    text: str

    def matches(self, flags: Optional[int]) -> bool:
        if flags is None:
            return False
        if self.exact:
            return flags == self.mask
        return flags & self.mask == self.mask


@dataclass(frozen=True)
class PacketFilter:
    tcp_flags: Optional[TcpFlagsFilter] = None
    icmp_types: Optional[frozenset[int]] = None

    def matches(self, packet) -> bool:
        if self.tcp_flags is not None and not self.tcp_flags.matches(getattr(packet, "tcp_flags", None)):
            return False
        if self.icmp_types is not None and getattr(packet, "icmp_type", None) not in self.icmp_types:
            return False
        return True


@dataclass(frozen=True)
class ProtocolDetection:
    """Every packet that passes the rule header and packet filter matches."""

    packet_filter: PacketFilter = PacketFilter()
    type: str = "protocol"
    event: str = EVENT_PACKET


@dataclass(frozen=True)
class ContentDetection:
    """Literal strings searched in one or more buffers (Aho-Corasick in Phase 6)."""

    buffers: tuple[str, ...]
    patterns: tuple[str, ...]
    nocase: bool = True
    match_all: bool = False
    event: str = EVENT_HTTP
    type: str = "content"


@dataclass(frozen=True)
class RegexDetection:
    buffers: tuple[str, ...]
    patterns: tuple[str, ...]
    compiled: tuple[re.Pattern, ...]
    nocase: bool = True
    event: str = EVENT_HTTP
    type: str = "regex"


@dataclass(frozen=True)
class ThresholdDetection:
    """At least `count` matching packets for one tracking key within `seconds`."""

    count: int
    seconds: float
    track: str = "by_src"
    packet_filter: PacketFilter = PacketFilter()
    type: str = "threshold"
    event: str = EVENT_PACKET


@dataclass(frozen=True)
class ScanDetection:
    """A scan episode of this technique that probed enough ports within `seconds`."""

    technique: str
    unique_dst_ports: int
    seconds: float
    type: str = "scan"
    event: str = EVENT_SCAN


@dataclass(frozen=True)
class DnsTunnelDetection:
    """`count` distinct long, high-entropy subdomains of one domain within `seconds`."""

    min_subdomain_length: int = 24
    min_entropy: float = 3.0
    count: int = 10
    seconds: float = 60.0
    type: str = "dns_tunnel"
    event: str = EVENT_PACKET


Detection = Union[
    ProtocolDetection, ContentDetection, RegexDetection, ThresholdDetection, ScanDetection, DnsTunnelDetection
]
Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass(frozen=True)
class EndpointMatch:
    """IP networks and port ranges; None means any."""

    networks: Optional[tuple[Network, ...]] = None
    ports: Optional[tuple[tuple[int, int], ...]] = None

    def matches(self, ip: Optional[str], port: Optional[int]) -> bool:
        if self.networks is not None:
            if ip is None:
                return False
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                return False
            if not any(address in network for network in self.networks):
                return False
        if self.ports is not None:
            if port is None or not any(low <= port <= high for low, high in self.ports):
                return False
        return True


ANY_ENDPOINT = EndpointMatch()


@dataclass
class Rule:
    sid: int
    name: str
    severity: str
    protocol: str
    detection: Detection
    rev: int = 1
    description: str = ""
    category: str = "uncategorized"
    enabled: bool = True
    source: EndpointMatch = ANY_ENDPOINT
    destination: EndpointMatch = ANY_ENDPOINT
    direction: str = "any"
    suppress: float = 0.0
    supersedes: tuple[int, ...] = ()
    tags: tuple[str, ...] = ()
    source_file: str = ""

    @property
    def event(self) -> str:
        return self.detection.event

    def endpoints_match(self, src_ip, src_port, dst_ip, dst_port) -> bool:
        return self.source.matches(src_ip, src_port) and self.destination.matches(dst_ip, dst_port)

    def direction_matches(self, is_forward: bool) -> bool:
        if self.direction == "to_server":
            return is_forward
        if self.direction == "to_client":
            return not is_forward
        return True

    def summary(self) -> str:
        state = "enabled" if self.enabled else "disabled"
        return (
            f"sid={self.sid} rev={self.rev} {self.name} [{self.severity}] "
            f"{self.protocol}/{self.detection.type} event={self.event} {state} ({self.source_file})"
        )


@dataclass
class RuleSet:
    """All loaded rules, indexed by SID."""

    rules: dict[int, Rule] = field(default_factory=dict)
    variables: dict[str, Any] = field(default_factory=dict)
    files: list[Path] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(sorted(self.rules.values(), key=lambda rule: rule.sid))

    def get(self, sid: int) -> Rule:
        try:
            return self.rules[sid]
        except KeyError:
            raise KeyError(f"unknown SID {sid}") from None

    def enabled_rules(self) -> list[Rule]:
        return [rule for rule in self if rule.enabled]

    def set_enabled(self, sid: int, enabled: bool) -> None:
        self.get(sid).enabled = enabled

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for rule in self.enabled_rules():
            counts[rule.detection.type] = counts.get(rule.detection.type, 0) + 1
        return counts


class _Collector:
    """Collect validation errors with a location prefix instead of stopping at the first one."""

    def __init__(self):
        self.errors: list[str] = []

    def add(self, where: str, message: str) -> None:
        self.errors.append(f"{where}: {message}")


def _expand(value: Any, variables: dict[str, Any], where: str, errors: _Collector) -> Any:
    """Replace "$NAME" (whole value or list item) by the variable's value."""
    if isinstance(value, str):
        match = _VARIABLE.match(value)
        if match:
            name = match.group(1)
            if name not in variables:
                errors.add(where, f"undefined variable ${name}")
                return None
            return variables[name]
        return value
    if isinstance(value, list):
        expanded = []
        for item in value:
            item = _expand(item, variables, where, errors)
            if isinstance(item, list):
                expanded.extend(item)
            elif item is not None:
                expanded.append(item)
        return expanded
    return value


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def _check_keys(data: dict, allowed: frozenset, where: str, errors: _Collector) -> None:
    for key in data:
        if key not in allowed:
            errors.add(where, f"unknown key '{key}' (allowed: {', '.join(sorted(allowed))})")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _parse_networks(value: Any, where: str, errors: _Collector) -> Optional[tuple[Network, ...]]:
    if value is None or value == "any":
        return None
    networks = []
    for item in _as_list(value):
        try:
            networks.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            errors.add(where, f"invalid IP or CIDR '{item}'")
    return tuple(networks)


def _parse_ports(value: Any, where: str, errors: _Collector) -> Optional[tuple[tuple[int, int], ...]]:
    if value is None or value == "any":
        return None
    ranges = []
    for item in _as_list(value):
        if _is_int(item):
            low = high = item
        else:
            match = _PORT_RANGE.match(str(item))
            if not match:
                errors.add(where, f"invalid port '{item}' (use 80 or \"1024-65535\")")
                continue
            low, high = int(match.group(1)), int(match.group(2))
        if not 0 <= low <= high <= 65535:
            errors.add(where, f"port out of range '{item}'")
            continue
        ranges.append((low, high))
    return tuple(ranges)


def _parse_endpoint(value: Any, where: str, variables, errors: _Collector) -> EndpointMatch:
    if value is None:
        return ANY_ENDPOINT
    if not isinstance(value, dict):
        errors.add(where, "must be a mapping with 'ips' and/or 'ports'")
        return ANY_ENDPOINT
    _check_keys(value, ENDPOINT_KEYS, where, errors)
    ips = _expand(value.get("ips"), variables, where, errors)
    ports = _expand(value.get("ports"), variables, where, errors)
    return EndpointMatch(
        networks=_parse_networks(ips, f"{where}.ips", errors),
        ports=_parse_ports(ports, f"{where}.ports", errors),
    )


def _parse_tcp_flags(value: Any, where: str, errors: _Collector) -> Optional[TcpFlagsFilter]:
    text = str(value).upper()
    exact = not text.endswith("+")
    letters = text.rstrip("+")
    if not letters or any(letter not in TCP_FLAG_LETTERS for letter in letters):
        errors.add(where, f"invalid tcp_flags '{value}' (letters {''.join(TCP_FLAG_LETTERS)}, optional '+')")
        return None
    mask = 0
    for letter in letters:
        mask |= TCP_FLAG_LETTERS[letter]
    return TcpFlagsFilter(mask, exact, str(value))


def _parse_packet_filter(data: dict, protocol: str, where: str, errors: _Collector) -> PacketFilter:
    tcp_flags = None
    icmp_types = None
    if "tcp_flags" in data:
        if protocol != "tcp":
            errors.add(where, "tcp_flags needs protocol tcp")
        tcp_flags = _parse_tcp_flags(data["tcp_flags"], f"{where}.tcp_flags", errors)
    if "icmp_type" in data:
        if protocol != "icmp":
            errors.add(where, "icmp_type needs protocol icmp")
        types = _as_list(data["icmp_type"])
        if not all(_is_int(item) and 0 <= item <= 255 for item in types):
            errors.add(where, "icmp_type must be integers 0-255")
        else:
            icmp_types = frozenset(types)
    return PacketFilter(tcp_flags, icmp_types)


def _one_of(data: dict, single: str, plural: str, where: str, errors: _Collector) -> tuple:
    """Accept `pattern: x` or `patterns: [x, y]` (same for buffer/buffers)."""
    if (single in data) == (plural in data):
        errors.add(where, f"give exactly one of '{single}' or '{plural}'")
        return ()
    values = _as_list(data.get(single, data.get(plural)))
    if not values or not all(isinstance(item, str) and item for item in values):
        errors.add(where, f"'{single}'/'{plural}' must be non-empty strings")
        return ()
    return tuple(values)


def _positive(data: dict, key: str, where: str, errors: _Collector, default=None, integer=False):
    value = data.get(key, default)
    valid = _is_int(value) if integer else _is_number(value)
    if not valid or value <= 0:
        kind = "a positive integer" if integer else "a positive number"
        errors.add(where, f"'{key}' must be {kind}")
        return default if default is not None else 1
    return value


def _payload_event(buffers: tuple[str, ...], protocol: str, where: str, errors: _Collector) -> str:
    unknown = [name for name in buffers if name not in HTTP_BUFFERS | PACKET_BUFFERS]
    if unknown:
        allowed = ", ".join(sorted(HTTP_BUFFERS | PACKET_BUFFERS))
        errors.add(where, f"unknown buffer {', '.join(unknown)} (allowed: {allowed})")
        return EVENT_HTTP
    if all(name in HTTP_BUFFERS for name in buffers):
        if protocol != "tcp":
            errors.add(where, "http_* buffers need protocol tcp")
        return EVENT_HTTP
    if all(name in PACKET_BUFFERS for name in buffers):
        return EVENT_PACKET
    errors.add(where, "do not mix http_* and packet buffers in one rule")
    return EVENT_HTTP


def _parse_detection(data: Any, protocol: str, where: str, errors: _Collector) -> Optional[Detection]:
    if not isinstance(data, dict):
        errors.add(where, "must be a mapping with a 'type'")
        return None
    kind = data.get("type")
    if kind not in DETECTION_KEYS:
        errors.add(where, f"unknown type '{kind}' (allowed: {', '.join(DETECTION_KEYS)})")
        return None
    _check_keys(data, DETECTION_KEYS[kind], where, errors)

    if kind == "protocol":
        return ProtocolDetection(_parse_packet_filter(data, protocol, where, errors))

    if kind in ("content", "regex"):
        buffers = _one_of(data, "buffer", "buffers", where, errors)
        patterns = _one_of(data, "pattern", "patterns", where, errors)
        nocase = data.get("nocase", True)
        if not isinstance(nocase, bool):
            errors.add(where, "'nocase' must be true or false")
            nocase = True
        event = _payload_event(buffers, protocol, where, errors) if buffers else EVENT_HTTP
        if kind == "content":
            match = data.get("match", "any")
            if match not in ("any", "all"):
                errors.add(where, "'match' must be 'any' or 'all'")
            stored = tuple(pattern.lower() for pattern in patterns) if nocase else patterns
            return ContentDetection(buffers, stored, nocase, match == "all", event)
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE if nocase else 0))
            except re.error as error:
                errors.add(where, f"invalid regex {pattern!r}: {error}")
        return RegexDetection(buffers, patterns, tuple(compiled), nocase, event)

    if kind == "threshold":
        track = data.get("track", "by_src")
        if track not in TRACKS:
            errors.add(where, f"'track' must be one of {', '.join(TRACKS)}")
        return ThresholdDetection(
            count=_positive(data, "count", where, errors, integer=True),
            seconds=_positive(data, "seconds", where, errors),
            track=track,
            packet_filter=_parse_packet_filter(data, protocol, where, errors),
        )

    if kind == "scan":
        if protocol != "tcp":
            errors.add(where, "scan detection needs protocol tcp")
        technique = data.get("technique")
        if technique not in SCAN_TECHNIQUES:
            errors.add(where, f"'technique' must be one of {', '.join(SCAN_TECHNIQUES)}")
        ports = _positive(data, "unique_dst_ports", where, errors, integer=True)
        if ports < 2:
            errors.add(where, "'unique_dst_ports' must be at least 2")
        return ScanDetection(technique, ports, _positive(data, "seconds", where, errors))

    if protocol != "udp":
        errors.add(where, "dns_tunnel detection needs protocol udp")
    return DnsTunnelDetection(
        min_subdomain_length=_positive(data, "min_subdomain_length", where, errors, 24, integer=True),
        min_entropy=_positive(data, "min_entropy", where, errors, 3.0),
        count=_positive(data, "count", where, errors, 10, integer=True),
        seconds=_positive(data, "seconds", where, errors, 60.0),
    )


def _check_header(rule: Rule, where: str, errors: _Collector) -> None:
    """Combinations of header and detection that can never match."""
    has_ports = rule.source.ports is not None or rule.destination.ports is not None
    if has_ports and rule.protocol not in ("tcp", "udp"):
        errors.add(where, "ports need protocol tcp or udp")
    if rule.event == EVENT_SCAN and has_ports:
        errors.add(where, "scan rules match hosts only, remove 'ports'")
    if rule.event in (EVENT_HTTP, EVENT_SCAN) and rule.direction == "to_client":
        errors.add(where, f"{rule.event} events are client -> server, direction to_client never matches")


def parse_rule(data: Any, variables: dict[str, Any], where: str, errors: _Collector) -> Optional[Rule]:
    if not isinstance(data, dict):
        errors.add(where, "a rule must be a mapping")
        return None
    sid = data.get("sid")
    if _is_int(sid):
        where = f"{where} (sid {sid})"
    _check_keys(data, RULE_KEYS, where, errors)
    before = len(errors.errors)

    if not _is_int(sid) or sid <= 0:
        errors.add(where, "'sid' must be a positive integer")
    rev = data.get("rev", 1)
    if not _is_int(rev) or rev < 1:
        errors.add(where, "'rev' must be an integer >= 1")
    name = data.get("name")
    if not isinstance(name, str) or not _NAME.match(name):
        errors.add(where, "'name' must look like SQL_INJECTION_UNION_SELECT")
    severity = data.get("severity")
    if severity not in SEVERITIES:
        errors.add(where, f"'severity' must be one of {', '.join(SEVERITIES)}")
    protocol = data.get("protocol")
    if protocol not in PROTOCOLS:
        errors.add(where, f"'protocol' must be one of {', '.join(PROTOCOLS)}")
        protocol = "ip"
    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        errors.add(where, "'enabled' must be true or false")
    for key in ("description", "category"):
        if key in data and not isinstance(data[key], str):
            errors.add(where, f"'{key}' must be a string")

    flow = data.get("flow") or {}
    direction = "any"
    if not isinstance(flow, dict):
        errors.add(where, "'flow' must be a mapping")
    else:
        _check_keys(flow, FLOW_KEYS, f"{where}.flow", errors)
        direction = flow.get("direction", "any")
        if direction not in DIRECTIONS:
            errors.add(where, f"'flow.direction' must be one of {', '.join(DIRECTIONS)}")

    suppress = data.get("suppress", 0)
    if not _is_number(suppress) or suppress < 0:
        errors.add(where, "'suppress' must be a number of seconds >= 0")
        suppress = 0
    supersedes = _as_list(data.get("supersedes", []))
    if not all(_is_int(item) for item in supersedes):
        errors.add(where, "'supersedes' must be a list of SIDs")
        supersedes = []
    tags = _as_list(data.get("tags", []))
    if not all(isinstance(item, str) for item in tags):
        errors.add(where, "'tags' must be a list of strings")
        tags = []

    detection = _parse_detection(data.get("detection"), protocol, f"{where}.detection", errors)
    source = _parse_endpoint(data.get("source"), f"{where}.source", variables, errors)
    destination = _parse_endpoint(data.get("destination"), f"{where}.destination", variables, errors)
    if len(errors.errors) > before or detection is None:
        return None

    rule = Rule(
        sid=sid,
        rev=rev,
        name=name,
        description=data.get("description", ""),
        category=data.get("category", "uncategorized"),
        severity=severity,
        enabled=enabled,
        protocol=protocol,
        source=source,
        destination=destination,
        direction=direction,
        detection=detection,
        suppress=float(suppress),
        supersedes=tuple(supersedes),
        tags=tuple(tags),
    )
    _check_header(rule, where, errors)
    return rule if len(errors.errors) == before else None


def _read_file(path: Path, errors: _Collector) -> Optional[dict]:
    try:
        with open(path, encoding="utf-8") as file:
            data = yaml.safe_load(file)
    except OSError as error:
        errors.add(str(path), f"cannot read file: {error}")
        return None
    except yaml.YAMLError as error:
        errors.add(str(path), f"YAML syntax error: {error}")
        return None
    if data is None:
        return {}
    if not isinstance(data, dict):
        errors.add(str(path), "top level must be a mapping with 'vars' and/or 'rules'")
        return None
    _check_keys(data, frozenset({"vars", "rules"}), str(path), errors)
    return data


def _collect_variables(documents, errors: _Collector) -> dict[str, Any]:
    variables: dict[str, Any] = {}
    for path, data in documents:
        values = data.get("vars") or {}
        if not isinstance(values, dict):
            errors.add(f"{path.name}.vars", "must be a mapping")
            continue
        for name, value in values.items():
            if not isinstance(name, str) or not _NAME.match(name):
                errors.add(f"{path.name}.vars", f"invalid variable name '{name}' (use UPPER_CASE)")
            elif name in variables and variables[name] != value:
                errors.add(f"{path.name}.vars", f"variable {name} redefined with a different value")
            else:
                variables[name] = value
    return variables


def _check_sid_references(rules: dict[int, Rule], errors: _Collector) -> None:
    for rule in rules.values():
        where = f"{rule.source_file} (sid {rule.sid})"
        for sid in rule.supersedes:
            if sid == rule.sid:
                errors.add(where, "a rule cannot supersede itself")
            elif sid not in rules:
                errors.add(where, f"supersedes unknown SID {sid}")
            elif rule.sid in rules[sid].supersedes:
                errors.add(where, f"rules {rule.sid} and {sid} supersede each other")
            elif rules[sid].event != rule.event:
                errors.add(where, f"supersedes SID {sid} which matches another event type")


def rule_files(paths: Iterable[Union[str, Path]]) -> list[Path]:
    """Expand directories to their *.yaml / *.yml files (sorted)."""
    files: list[Path] = []
    for path in paths:
        path = Path(path)
        if path.is_dir():
            files.extend(sorted(item for item in path.iterdir() if item.suffix in RULE_FILE_SUFFIXES))
        else:
            files.append(path)
    return files


def load_rules(paths: Iterable[Union[str, Path]] = (DEFAULT_RULES_DIR,)) -> RuleSet:
    """Load, validate and index rules. Raises RuleError listing every problem."""
    errors = _Collector()
    files = rule_files(paths)
    if not files:
        raise RuleError(["no rule files found"])
    documents = [(path, data) for path in files if (data := _read_file(path, errors)) is not None]
    variables = _collect_variables(documents, errors)

    rules: dict[int, Rule] = {}
    names: dict[str, int] = {}
    for path, data in documents:
        entries = data.get("rules") or []
        if not isinstance(entries, list):
            errors.add(path.name, "'rules' must be a list")
            continue
        for index, entry in enumerate(entries, start=1):
            rule = parse_rule(entry, variables, f"{path.name} rule #{index}", errors)
            if rule is None:
                continue
            rule.source_file = path.name
            if rule.sid in rules:
                errors.add(f"{path.name} rule #{index}", f"duplicate SID {rule.sid} (already in {rules[rule.sid].source_file})")
                continue
            if rule.name in names:
                errors.add(f"{path.name} rule #{index}", f"duplicate name {rule.name} (SID {names[rule.name]})")
                continue
            rules[rule.sid] = rule
            names[rule.name] = rule.sid

    _check_sid_references(rules, errors)
    if errors.errors:
        raise RuleError(errors.errors)
    return RuleSet(rules=rules, variables=variables, files=files)
