import sys
import time
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(WORKSPACE_ROOT / "ids" / "phase 4"))

from http_normalizer import (
    DOUBLE_ENCODING,
    EXCESSIVE_ENCODING,
    HTTP_AMBIGUOUS_LENGTH,
    HTTP_BAD_CHUNK,
    HTTP_CONFLICTING_LENGTH,
    HTTP_HEADER_TOO_LONG,
    HTTP_INCOMPLETE,
    HTTP_URI_SPACE,
    INVALID_PERCENT_ENCODING,
    NULL_BYTE,
    OVERLONG_UTF8,
    PATH_TRAVERSAL,
    SQL_COMMENT,
    UNICODE_ENCODING,
    HttpStreamParser,
    bytes_to_text,
    decode_chunked,
    decode_repeatedly,
    normalize_path,
    normalize_payload,
    normalize_text,
    percent_decode_once,
)

# Patterns of the rules planned in flow_build_IDS.md (Phase 6 will own them).
SID_10004_UNION_SELECT = "union select"
SID_10006_COMMAND = (";cat ", "|cat ", "&&cat ", "/etc/passwd")
SID_10007_XSS = "<script"


def parse_one(raw: bytes):
    parser = HttpStreamParser()
    requests = parser.feed(raw) + parser.finish()
    return requests[0]


def get(uri: bytes):
    return parse_one(b"GET " + uri + b" HTTP/1.1\r\nHost: victim\r\n\r\n")


class DecodingTests(unittest.TestCase):
    def test_percent_decode_once(self):
        self.assertEqual(percent_decode_once(b"a%20b%3c")[0], b"a b<")

    def test_plus_is_space_only_when_asked(self):
        self.assertEqual(percent_decode_once(b"a+b")[0], b"a+b")
        self.assertEqual(percent_decode_once(b"a+b", plus_as_space=True)[0], b"a b")

    def test_double_encoding(self):
        result = decode_repeatedly(b"%2527")
        self.assertEqual(result.value, b"'")
        self.assertEqual(result.rounds, 2)
        self.assertIn(DOUBLE_ENCODING, result.anomalies)

    def test_encoded_plus_stays_plus(self):
        self.assertEqual(decode_repeatedly(b"1%2B1", plus_as_space=True).value, b"1+1")

    def test_excessive_encoding(self):
        result = decode_repeatedly(b"%25252527", max_rounds=3)
        self.assertIn(EXCESSIVE_ENCODING, result.anomalies)

    def test_iis_unicode_encoding(self):
        value, anomalies = percent_decode_once(b"%u0055NION")
        self.assertEqual(value, b"UNION")
        self.assertIn(UNICODE_ENCODING, anomalies)

    def test_invalid_percent(self):
        self.assertIn(INVALID_PERCENT_ENCODING, percent_decode_once(b"100%zz")[1])

    def test_overlong_utf8_slash(self):
        text, anomalies = bytes_to_text(b"..\xc0\xafetc")
        self.assertEqual(text, "../etc")
        self.assertIn(OVERLONG_UTF8, anomalies)

    def test_null_byte_removed(self):
        text, anomalies = bytes_to_text(b"shell.php\x00.jpg")
        self.assertEqual(text, "shell.php.jpg")
        self.assertIn(NULL_BYTE, anomalies)


class TextNormalizationTests(unittest.TestCase):
    def test_path_normalization(self):
        cases = {
            "/a/./b//c": "/a/b/c",
            "/a/b/../c": "/a/c",
            "/../../etc/passwd": "/etc/passwd",
            "\\windows\\win.ini": "/windows/win.ini",
            "/dir/": "/dir/",
            "": "/",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_path(raw)[0], expected)
        self.assertIn(PATH_TRAVERSAL, normalize_path("/a/../b")[1])

    def test_sql_comment_removed(self):
        text, anomalies = normalize_text("1 UNION/**/SELECT/*x*/password")
        self.assertEqual(text, "1 union select password")
        self.assertIn(SQL_COMMENT, anomalies)

    def test_mysql_versioned_comment_keeps_its_body(self):
        self.assertEqual(normalize_text("UNION/*!50000SELECT*/1")[0], "union select 1")

    def test_unclosed_comment_is_kept_and_fast(self):
        self.assertEqual(normalize_text("a /* open")[0], "a /* open")
        start = time.perf_counter()
        normalize_text("/*" * 200_000)
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_whitespace_and_case(self):
        self.assertEqual(normalize_text("UNION\t\n  SELECT")[0], "union select")

    def test_html_entities(self):
        self.assertEqual(normalize_text("&lt;SCRIPT&gt;")[0], "<script>")

    def test_normalize_payload_keeps_raw(self):
        raw = b"%55NION+SELECT"
        result = normalize_payload(raw, plus_as_space=True)
        self.assertEqual(result.raw, raw)
        self.assertEqual(result.decoded, "UNION SELECT")
        self.assertEqual(result.normalized, "union select")


class RuleBufferTests(unittest.TestCase):
    """The normalized buffers must make the planned rules match evasive variants."""

    def test_sid_10004_union_select_variants(self):
        variants = [
            b"/p?id=1 UNION SELECT 1",
            b"/p?id=1+UnIoN+SeLeCt+1",
            b"/p?id=1%20UNION%20SELECT%201",
            b"/p?id=1%2520UNION%2520SELECT%25201",
            b"/p?id=1+UNION/**/SELECT+1",
            b"/p?id=1+%u0055NION%09SELECT+1",
        ]
        for uri in variants:
            with self.subTest(uri=uri):
                self.assertIn(SID_10004_UNION_SELECT, get(uri).uri_normalized)

    def test_sid_10006_command_injection(self):
        request = get(b"/ping?host=127.0.0.1;cat+/etc/passwd")
        self.assertTrue(all(
            pattern in request.uri_normalized for pattern in (";cat ", "/etc/passwd")
        ))

    def test_sid_10007_encoded_script_tag(self):
        for uri in (b"/c?t=%3Cscript%3Ealert(1)", b"/c?t=%253CSCRIPT%253E", b"/c?t=&lt;script&gt;"):
            with self.subTest(uri=uri):
                self.assertIn(SID_10007_XSS, get(uri).uri_normalized)

    def test_raw_spaces_in_uri_are_kept(self):
        request = get(b"/index.php?id=1 UNION SELECT username,password FROM users")
        self.assertEqual(request.version, "HTTP/1.1")
        self.assertIn("union select username,password from users", request.uri_normalized)
        self.assertIn(HTTP_URI_SPACE, request.anomalies)

    def test_encoded_question_mark_is_part_of_path(self):
        request = get(b"/a%3Fb?c=d")
        self.assertEqual(request.path_raw, "/a%3Fb")
        self.assertEqual(request.query_raw, "c=d")
        self.assertEqual(request.uri_decoded, "/a?b?c=d")


class HttpParserTests(unittest.TestCase):
    def test_pipelined_requests(self):
        parser = HttpStreamParser()
        requests = parser.feed(b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual([request.uri_raw for request in requests], ["/a", "/b"])
        self.assertEqual(requests[1].offset, 19)
        self.assertEqual(requests[1].header("HOST"), "x")

    def test_byte_by_byte_feed(self):
        raw = b"POST /login HTTP/1.1\r\nContent-Length: 9\r\n\r\nuser=root"
        parser = HttpStreamParser()
        requests = []
        for index in range(len(raw)):
            requests += parser.feed(raw[index:index + 1])
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].body, b"user=root")

    def test_form_body_is_decoded(self):
        request = parse_one(
            b"POST /l HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 21\r\n\r\nq=1%27+UNION+SELECT+1"
        )
        self.assertEqual(request.body_normalized, "q=1' union select 1")

    def test_chunked_body(self):
        request = parse_one(
            b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nUNIO\r\n8\r\nN SELECT\r\n0\r\n\r\n"
        )
        self.assertEqual(request.body, b"UNION SELECT")

    def test_decode_chunked_incomplete_and_bad(self):
        self.assertIsNone(decode_chunked(b"4\r\nUN"))
        self.assertEqual(decode_chunked(b"2\r\nhi\r\n0\r\n\r\n"), (b"hi", 12))
        parser = HttpStreamParser()
        requests = parser.feed(b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")
        self.assertIn(HTTP_BAD_CHUNK, requests[0].anomalies)
        self.assertTrue(parser.stopped)

    def test_incomplete_request_at_finish(self):
        parser = HttpStreamParser()
        self.assertEqual(parser.feed(b"GET /half HTTP/1.1\r\nHost: x"), [])
        requests = parser.finish()
        self.assertEqual(requests[0].uri_raw, "/half")
        self.assertIn(HTTP_INCOMPLETE, requests[0].anomalies)

    def test_non_http_stream_is_ignored(self):
        parser = HttpStreamParser()
        self.assertEqual(parser.feed(b"SSH-2.0-OpenSSH_9.6\r\n"), [])
        self.assertFalse(parser.is_http)
        self.assertEqual(parser.finish(), [])

    def test_request_smuggling_headers(self):
        conflicting = parse_one(
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"
        )
        self.assertIn(HTTP_CONFLICTING_LENGTH, conflicting.anomalies)
        ambiguous = parse_one(
            b"POST / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )
        self.assertIn(HTTP_AMBIGUOUS_LENGTH, ambiguous.anomalies)

    def test_header_too_long(self):
        parser = HttpStreamParser(max_header_bytes=32)
        parser.feed(b"GET / HTTP/1.1\r\nX: " + b"a" * 64)
        self.assertTrue(parser.stopped)
        self.assertIn(HTTP_HEADER_TOO_LONG, parser.anomalies)


if __name__ == "__main__":
    unittest.main()
