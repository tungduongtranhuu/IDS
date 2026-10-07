"""Phase 4 payload normalization and HTTP request parsing.

Turns the reassembled client -> server byte stream into HTTP requests with
three views of the URI, so rules match the meaning instead of the encoding:

    uri_raw         exactly as sent                  (evidence)
    uri_decoded     URL-decoded, case kept           (regex rules, e.g. SID 10005)
    uri_normalized  decoded + path resolved + SQL comments removed
                    + HTML entities + lowercase + whitespace collapsed
                                                      (content rules, e.g. SID 10004)

The raw bytes are never overwritten.
"""

import html
import re
from dataclasses import dataclass, field
from typing import Optional


DEFAULT_MAX_DECODE_ROUNDS = 3
DEFAULT_MAX_HEADER_BYTES = 64 * 1024
DEFAULT_MAX_BODY_BYTES = 1024 * 1024

DOUBLE_ENCODING = "DOUBLE_ENCODING"
EXCESSIVE_ENCODING = "EXCESSIVE_ENCODING"
UNICODE_ENCODING = "UNICODE_ENCODING"
INVALID_PERCENT_ENCODING = "INVALID_PERCENT_ENCODING"
OVERLONG_UTF8 = "OVERLONG_UTF8"
INVALID_UTF8 = "INVALID_UTF8"
NULL_BYTE = "NULL_BYTE"
PATH_TRAVERSAL = "PATH_TRAVERSAL"
SQL_COMMENT = "SQL_COMMENT"
HTTP_MALFORMED = "HTTP_MALFORMED"
HTTP_INCOMPLETE = "HTTP_INCOMPLETE"
HTTP_HEADER_TOO_LONG = "HTTP_HEADER_TOO_LONG"
HTTP_BAD_CHUNK = "HTTP_BAD_CHUNK"
HTTP_CONFLICTING_LENGTH = "HTTP_CONFLICTING_LENGTH"
HTTP_AMBIGUOUS_LENGTH = "HTTP_AMBIGUOUS_LENGTH"
HTTP_URI_SPACE = "HTTP_URI_SPACE"

HTTP_METHODS = frozenset(
    {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT"}
)

_PERCENT = re.compile(rb"%(?:[uU]([0-9a-fA-F]{4})|([0-9a-fA-F]{2}))")
_BAD_PERCENT = re.compile(rb"%(?![0-9a-fA-F]{2}|[uU][0-9a-fA-F]{4})")
_OVERLONG = re.compile(rb"[\xc0\xc1][\x80-\xbf]")
_WHITESPACE = re.compile(r"\s+")


@dataclass
class DecodeResult:
    value: bytes
    rounds: int
    anomalies: set[str]


def percent_decode_once(data: bytes, plus_as_space: bool = False) -> tuple[bytes, set[str]]:
    """Decode %XX and %uXXXX once. '+' becomes a space only in query/form data."""
    anomalies = set()
    if plus_as_space:
        data = data.replace(b"+", b" ")
    if _BAD_PERCENT.search(data):
        anomalies.add(INVALID_PERCENT_ENCODING)

    def replace(match: re.Match) -> bytes:
        if match.group(1):
            anomalies.add(UNICODE_ENCODING)
            return chr(int(match.group(1), 16)).encode("utf-8", "replace")
        return bytes([int(match.group(2), 16)])

    return _PERCENT.sub(replace, data), anomalies


def decode_repeatedly(
    data: bytes,
    max_rounds: int = DEFAULT_MAX_DECODE_ROUNDS,
    plus_as_space: bool = False,
) -> DecodeResult:
    """Decode until the value stops changing (catches %2527 -> %27 -> ')."""
    anomalies: set[str] = set()
    rounds = 0
    current = data
    for index in range(max_rounds):
        decoded, found = percent_decode_once(current, plus_as_space and index == 0)
        anomalies |= found
        if decoded == current:
            break
        rounds += 1
        current = decoded
    else:
        if percent_decode_once(current)[0] != current:
            anomalies.add(EXCESSIVE_ENCODING)
    if rounds >= 2:
        anomalies.add(DOUBLE_ENCODING)
    return DecodeResult(current, rounds, anomalies)


def bytes_to_text(data: bytes) -> tuple[str, set[str]]:
    """Bytes -> str, removing NUL bytes and folding overlong UTF-8 (%c0%af = '/')."""
    anomalies = set()
    if b"\x00" in data:
        anomalies.add(NULL_BYTE)
        data = data.replace(b"\x00", b"")
    if _OVERLONG.search(data):
        anomalies.add(OVERLONG_UTF8)
        data = _OVERLONG.sub(
            lambda match: bytes([((match.group()[0] & 0x1F) << 6) | (match.group()[1] & 0x3F)]),
            data,
        )
    try:
        return data.decode("utf-8"), anomalies
    except UnicodeDecodeError:
        anomalies.add(INVALID_UTF8)
        return data.decode("latin-1"), anomalies


def normalize_path(path: str) -> tuple[str, set[str]]:
    """Resolve '\\', '//', '.' and '..' like a web server would."""
    anomalies = set()
    path = path.replace("\\", "/")
    segments: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            anomalies.add(PATH_TRAVERSAL)
            if segments:
                segments.pop()
            continue
        segments.append(part)
    normalized = "/" + "/".join(segments)
    if path.endswith("/") and segments:
        normalized += "/"
    return normalized, anomalies


def strip_sql_comments(text: str) -> tuple[str, bool]:
    """Replace /* ... */ with a space in one linear pass (no regex backtracking).

    MySQL executes the body of /*!50000 ... */, so that body is kept.
    An unclosed /* is left as it is.
    """
    parts = []
    position = 0
    found = False
    while True:
        start = text.find("/*", position)
        end = text.find("*/", start + 2) if start >= 0 else -1
        if end < 0:
            parts.append(text[position:])
            return "".join(parts), found
        found = True
        parts.append(text[position:start])
        body = text[start + 2:end]
        parts.append(f" {body[1:].lstrip('0123456789')} " if body.startswith("!") else " ")
        position = end + 2


def normalize_text(text: str) -> tuple[str, set[str]]:
    """HTML entities, SQL comments, lowercase and whitespace normalization."""
    anomalies = set()
    text = html.unescape(text)
    text, found = strip_sql_comments(text)
    if found:
        anomalies.add(SQL_COMMENT)
    text = _WHITESPACE.sub(" ", text.lower()).strip()
    return text, anomalies


@dataclass
class NormalizedPayload:
    raw: bytes
    decoded: str
    normalized: str
    decode_rounds: int
    anomalies: tuple[str, ...]


def normalize_payload(
    data: bytes,
    url_decode: bool = True,
    plus_as_space: bool = False,
    max_rounds: int = DEFAULT_MAX_DECODE_ROUNDS,
) -> NormalizedPayload:
    """Generic normalization for any payload (non-HTTP buffers, request bodies)."""
    anomalies: set[str] = set()
    rounds = 0
    value = data
    if url_decode:
        result = decode_repeatedly(data, max_rounds, plus_as_space)
        value, rounds = result.value, result.rounds
        anomalies |= result.anomalies
    decoded, found = bytes_to_text(value)
    anomalies |= found
    normalized, found = normalize_text(decoded)
    anomalies |= found
    return NormalizedPayload(data, decoded, normalized, rounds, tuple(sorted(anomalies)))


@dataclass
class HttpRequest:
    """One HTTP request from a client stream, with raw and normalized buffers."""

    offset: int
    method: str
    version: str
    uri_raw: str
    path_raw: str
    query_raw: Optional[str]
    headers: list[tuple[str, str]]
    body: bytes
    uri_decoded: str = ""
    path_normalized: str = ""
    uri_normalized: str = ""
    body_normalized: str = ""
    decode_rounds: int = 0
    anomalies: tuple[str, ...] = ()

    def header(self, name: str) -> Optional[str]:
        name = name.lower()
        for header_name, value in self.headers:
            if header_name.lower() == name:
                return value
        return None


def build_http_request(
    offset: int,
    method: bytes,
    uri: bytes,
    version: bytes,
    headers: list[tuple[str, str]],
    body: bytes,
    extra_anomalies: set[str],
    max_rounds: int = DEFAULT_MAX_DECODE_ROUNDS,
) -> HttpRequest:
    anomalies = set(extra_anomalies)
    # Split on the raw '?': an encoded %3F is part of the path, not a separator.
    path_raw, separator, query_raw = uri.partition(b"?")
    has_query = bool(separator)

    path_result = decode_repeatedly(path_raw, max_rounds)
    path_text, found = bytes_to_text(path_result.value)
    anomalies |= path_result.anomalies | found
    rounds = path_result.rounds

    query_text = ""
    if has_query:
        query_result = decode_repeatedly(query_raw, max_rounds, plus_as_space=True)
        query_text, found = bytes_to_text(query_result.value)
        anomalies |= query_result.anomalies | found
        rounds = max(rounds, query_result.rounds)

    path_normalized, found = normalize_path(path_text)
    anomalies |= found
    uri_decoded = path_text + ("?" + query_text if has_query else "")
    uri_normalized, found = normalize_text(path_normalized + ("?" + query_text if has_query else ""))
    anomalies |= found

    content_type = next((value for name, value in headers if name.lower() == "content-type"), "")
    body_view = normalize_payload(
        body,
        url_decode="application/x-www-form-urlencoded" in content_type.lower(),
        plus_as_space=True,
        max_rounds=max_rounds,
    )
    anomalies |= set(body_view.anomalies)

    return HttpRequest(
        offset=offset,
        method=method.decode("latin-1"),
        version=version.decode("latin-1"),
        uri_raw=uri.decode("latin-1"),
        path_raw=path_raw.decode("latin-1"),
        query_raw=query_raw.decode("latin-1") if has_query else None,
        headers=headers,
        body=body,
        uri_decoded=uri_decoded,
        path_normalized=path_normalized,
        uri_normalized=uri_normalized,
        body_normalized=body_view.normalized,
        decode_rounds=max(rounds, body_view.decode_rounds),
        anomalies=tuple(sorted(anomalies)),
    )


class ChunkError(ValueError):
    pass


def decode_chunked(data: bytes) -> Optional[tuple[bytes, int]]:
    """Decode a chunked body. Return (body, bytes consumed) or None if incomplete."""
    position = 0
    body = bytearray()
    while True:
        line_end = data.find(b"\r\n", position)
        if line_end < 0:
            return None
        size_text = data[position:line_end].split(b";")[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as error:
            raise ChunkError(f"bad chunk size {size_text!r}") from error
        position = line_end + 2
        if size == 0:
            if data[position:position + 2] == b"\r\n":
                return bytes(body), position + 2
            trailer_end = data.find(b"\r\n\r\n", position)
            if trailer_end < 0:
                return None
            return bytes(body), trailer_end + 4
        if len(data) < position + size + 2:
            return None
        body += data[position:position + size]
        position += size + 2


def parse_request_line(line: bytes) -> Optional[tuple[bytes, bytes, bytes, bool]]:
    """Split 'METHOD URI VERSION'. Return (method, uri, version, uri_has_space).

    Raw spaces in the URI are invalid, but attackers send them
    ("GET /p?id=1 UNION SELECT 1 HTTP/1.1"), so everything between the
    method and the final HTTP/x token is kept as the URI.
    """
    parts = line.split()
    if len(parts) < 2:
        return None
    method = parts[0]
    if len(parts) > 2 and parts[-1].upper().startswith(b"HTTP/"):
        version = parts[-1]
        uri = line.strip()[len(method):-len(version)].strip()
    else:
        version = b"HTTP/0.9"
        uri = line.strip()[len(method):].strip()
    return method, uri, version, b" " in uri or b"\t" in uri


def _find_header_end(buffer: bytes) -> tuple[int, int]:
    """Return (index, separator length) of the blank line ending the headers."""
    candidates = [
        (index, length)
        for index, length in ((buffer.find(b"\r\n\r\n"), 4), (buffer.find(b"\n\n"), 2))
        if index >= 0
    ]
    return min(candidates) if candidates else (-1, 0)


class HttpStreamParser:
    """Incremental HTTP/1.x request parser fed with reassembled stream bytes.

    feed() returns every request that became complete. finish() is called at
    the end of the connection and returns a last, partial request if any.
    A stream that does not start with an HTTP method is ignored (is_http=False).
    """

    def __init__(
        self,
        max_rounds: int = DEFAULT_MAX_DECODE_ROUNDS,
        max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    ):
        self.max_rounds = max_rounds
        self.max_header_bytes = max_header_bytes
        self.max_body_bytes = max_body_bytes
        self.buffer = bytearray()
        self.buffer_offset = 0
        self.is_http: Optional[bool] = None
        self.stopped = False
        self.requests: list[HttpRequest] = []
        self.anomalies: set[str] = set()

    def feed(self, data: bytes) -> list[HttpRequest]:
        if self.stopped:
            return []
        self.buffer.extend(data)
        return self._parse(final=False)

    def finish(self) -> list[HttpRequest]:
        if self.stopped:
            return []
        requests = self._parse(final=True)
        self.stopped = True
        return requests

    def _parse(self, final: bool) -> list[HttpRequest]:
        parsed = []
        while not self.stopped:
            request = self._parse_one(final)
            if request is None:
                break
            parsed.append(request)
        self.requests.extend(parsed)
        return parsed

    def _consume(self, count: int) -> None:
        del self.buffer[:count]
        self.buffer_offset += count

    def _stop(self, anomaly: Optional[str] = None) -> None:
        if anomaly:
            self.anomalies.add(anomaly)
        self.stopped = True

    def _parse_one(self, final: bool) -> Optional[HttpRequest]:
        # Empty lines between requests are allowed (RFC 9112 section 2.2).
        while self.buffer[:2] == b"\r\n" or self.buffer[:1] == b"\n":
            self._consume(2 if self.buffer[:2] == b"\r\n" else 1)
        if not self.buffer:
            return None

        first_space = self.buffer.find(b" ")
        if first_space < 0:
            if len(self.buffer) < 16 and not final:
                return None
            method = bytes(self.buffer[:16])
        else:
            method = bytes(self.buffer[:first_space])
        if method not in HTTP_METHODS:
            if self.is_http is None:
                self.is_http = False
                self._stop()
            else:
                self._stop(HTTP_MALFORMED)
            return None
        self.is_http = True

        header_end, separator = _find_header_end(bytes(self.buffer))
        if header_end < 0:
            if len(self.buffer) > self.max_header_bytes:
                self._stop(HTTP_HEADER_TOO_LONG)
                return None
            if not final:
                return None
            header_end, separator = len(self.buffer), 0

        head = bytes(self.buffer[:header_end])
        lines = [line.rstrip(b"\r") for line in head.split(b"\n")]
        anomalies: set[str] = set()
        request_line = parse_request_line(lines[0])
        if request_line is None:
            self._stop(HTTP_MALFORMED)
            return None
        _method, uri, version, uri_has_space = request_line
        if uri_has_space:
            anomalies.add(HTTP_URI_SPACE)

        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            name, colon, value = line.partition(b":")
            if not colon:
                anomalies.add(HTTP_MALFORMED)
                continue
            headers.append((name.strip().decode("latin-1"), value.strip().decode("latin-1")))

        body_start = header_end + separator
        available = bytes(self.buffer[body_start:])
        body, consumed, body_anomalies = self._read_body(headers, available, final)
        if body is None:
            return None
        anomalies |= body_anomalies
        if separator == 0:
            anomalies.add(HTTP_INCOMPLETE)

        offset = self.buffer_offset
        self._consume(body_start + consumed)
        return build_http_request(
            offset,
            method,
            uri,
            version,
            headers,
            body[:self.max_body_bytes],
            anomalies,
            self.max_rounds,
        )

    def _read_body(
        self, headers: list[tuple[str, str]], available: bytes, final: bool
    ) -> tuple[Optional[bytes], int, set[str]]:
        anomalies: set[str] = set()
        lengths = {value for name, value in headers if name.lower() == "content-length"}
        chunked = any(
            name.lower() == "transfer-encoding" and "chunked" in value.lower()
            for name, value in headers
        )
        if len(lengths) > 1:
            anomalies.add(HTTP_CONFLICTING_LENGTH)
        if chunked and lengths:
            anomalies.add(HTTP_AMBIGUOUS_LENGTH)

        if chunked:
            try:
                decoded = decode_chunked(available)
            except ChunkError:
                self._stop(HTTP_BAD_CHUNK)
                return available, len(available), anomalies | {HTTP_BAD_CHUNK}
            if decoded is None:
                if not final:
                    return None, 0, anomalies
                return available, len(available), anomalies | {HTTP_INCOMPLETE}
            body, consumed = decoded
            return body, consumed, anomalies

        if not lengths:
            return b"", 0, anomalies
        try:
            length = int(min(lengths))
        except ValueError:
            length = -1
        if length < 0:
            return b"", 0, anomalies | {HTTP_MALFORMED}
        if len(available) < length:
            if not final:
                return None, 0, anomalies
            return available, len(available), anomalies | {HTTP_INCOMPLETE}
        return available[:length], length, anomalies
