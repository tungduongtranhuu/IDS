# Báo cáo kỹ thuật Phase 4 – Anti-Evasion (IP Defrag, TCP Reassembly, Normalization)

Cập nhật: 2026-10-06

Phase 4 làm các mục của "PHASE 4 – ANTI-EVASION" trong `flow for build/flow_build_IDS.md` (§25), cũng là "Giai đoạn 3" trong `doc_for_phase.md`:

| Hạng mục roadmap | Module |
|---|---|
| IP fragmentation | `ip_defrag.py` |
| TCP reassembly, out-of-order, duplicate packets, overlap handling | `tcp_reassembly.py` (+ `sparse_buffer.py`) |
| URL decoding, lowercase, HTTP normalization | `http_normalizer.py` |
| Nối tất cả lại, CLI | `anti_evasion.py` |

| File | Dòng (≈) | Vai trò |
|---|---|---|
| `ids/phase 4/sparse_buffer.py` | 140 | Bộ đệm byte theo offset, có "lỗ"; phát hiện overlap. Dùng chung cho defrag và TCP |
| `ids/phase 4/ip_defrag.py` | 380 | Ghép mảnh IPv4 trên frame thô, **trước** decoder |
| `ids/phase 4/tcp_reassembly.py` | 350 | Ráp stream TCP theo sequence number, mỗi chiều riêng |
| `ids/phase 4/http_normalizer.py` | 520 | Giải mã URL nhiều lớp, chuẩn hoá path / text, parser HTTP chạy tăng dần |
| `ids/phase 4/anti_evasion.py` | 310 | `AntiEvasionPipeline` nối Phase 2 → 3 → 4, CLI ghi báo cáo |
| `tests/phase 4/` | | 94 test, bộ sinh PCAP tấn công, thư mục `results/` |

---

## 1. Kiến trúc

```
 PCAP / live ──(ts, raw frame)──► IpDefragmenter.process()          [ip_defrag]
                                     │ frame gốc, hoặc frame ghép từ N mảnh
                                     ▼
                              PacketDecoder.decode_ethernet()        [Phase 2]
                                     │ Packet (+ reassembled_fragments, defrag_anomalies)
                                     ▼
                              FlowManager.add_packet()               [Phase 3]
                     on_packet │                       │ on_flow_end
                               ▼                       ▼
                 TcpReassembler.process()     TcpReassembler.close_flow()  [tcp_reassembly]
                               │ on_data(stream, chiều, byte mới liền mạch)
                               ▼
                 HttpStreamParser.feed()                             [http_normalizer]
                               │ HttpRequest (raw / decoded / normalized)
                               ▼
                 stream.context["http"].requests ──► báo cáo / Phase 5–6 (rule)
```

### Vì sao sắp xếp như vậy

1. **Ghép mảnh IP trước decoder.** Khi gặp mảnh đầu, dpkt sẽ parse TCP từ dữ liệu bị cắt, còn các mảnh sau thì không có port. Ghép thành datagram hoàn chỉnh trước, thì decoder và flow manager không cần biết gì về fragment nữa. Cách này cũng đúng với RFC 791: chỉ host đích mới ghép mảnh, sau đó mới đến tầng transport.
2. **Ráp TCP theo từng packet** (qua hook `on_packet`), không đợi flow kết thúc. Detection phải bắt được SQLi ngay giữa một kết nối keep-alive.
3. **Parser HTTP chạy tăng dần** (`feed`): mỗi khi có thêm byte liền mạch thì parse luôn các request đã đủ.
4. **Giữ cả raw lẫn normalized** (yêu cầu ở §9 của roadmap): `stream.client.data` là byte gốc đã ráp; `HttpRequest` có `uri_raw`, `uri_decoded`, `uri_normalized`.

---

## 2. `sparse_buffer.py`

`SparseBuffer` là một `bytearray` đi kèm danh sách `ranges`: các đoạn `[start, end)` thực sự có dữ liệu, đã sắp xếp và gộp. Nhờ có `ranges`, bộ đệm phân biệt được "chưa có dữ liệu" với "dữ liệu là byte 0".

| Phương thức | Hoạt động |
|---|---|
| `write(offset, payload, policy)` | Mở rộng `data` nếu cần. Với mỗi đoạn đã có mà giao với `[offset, end)`: cộng `overlap_bytes`, so từng byte cũ với byte mới để đếm `conflict_bytes`. Sau đó ghi: policy `"last"` ghi đè toàn bộ; `"first"` chỉ ghi vào chỗ trống (`gaps`). Trả `WriteResult(new_bytes, overlap_bytes, conflict_bytes)` |
| `gaps(start, end)` | Các khoảng trống trong `[start, end)` |
| `contiguous_end(start)` | Điểm kết thúc của đoạn dữ liệu liền mạch chứa `start` |
| `pop_front(n)` | Lấy ra `n` byte đầu và dịch mọi offset lùi `n` (TCP dùng để đẩy byte đã liền mạch sang stream) |
| `covered_bytes`, `is_empty`, `chunks()` | Thống kê, và danh sách các đoạn còn lại |

**Overlap policy.** Khi hai mảnh / segment chồng nhau mà nội dung khác nhau, mỗi hệ điều hành giữ một bản khác nhau. Windows và đa số stack giữ bản **đến trước** (`first`); một số stack giữ bản **đến sau** (`last`). Snort gọi đây là *target-based policy*. Kẻ tấn công lợi dụng chỗ này: gửi hai phiên bản, để IDS và máy đích hiểu khác nhau. Phase 4 cho chọn policy, và **luôn** báo bất thường `*_OVERLAP_CONFLICT` bất kể policy là gì. Đây mới là tín hiệu quan trọng nhất.

---

## 3. `ip_defrag.py` – ghép mảnh IPv4

### 3.1 Đọc header không cần dpkt

`parse_ipv4_frame(raw)` đọc Ethernet, bỏ qua thẻ VLAN (`0x8100`, `0x88A8`, `0x9100`), đọc header IPv4 (IHL, total length, ID, flags/offset, protocol, src, dst) bằng `struct`, rồi cắt payload theo `total_length` (bỏ padding Ethernet). Frame không phải IPv4, hoặc không phải mảnh, được **trả nguyên vẹn** mà không qua dpkt, nên đường đi thông thường rất nhẹ.

### 3.2 Cấu trúc

- `FragmentDatagram`: các mảnh của một datagram, key `(src, dst, proto, ip_id)` (RFC 791). Gồm `SparseBuffer`, header lấy từ mảnh offset 0 (`link_header`, `ip_header`), `payload_length` (biết được khi gặp mảnh có MF=0: `offset + len`), số mảnh và danh sách bất thường.
- `DefragOutput`: frame trả cho decoder, kèm `fragment_count` và `anomalies`.
- `DefragEvent`: một sự kiện bất thường (thời điểm, IP, protocol, ip_id, chi tiết), gửi qua callback `on_anomaly`.

### 3.3 Thuật toán `IpDefragmenter.process(ts, raw)`

```
frame = parse_ipv4_frame(raw); không phải mảnh → trả nguyên frame
datagram = datagrams[key] hoặc tạo mới (bảng đầy → FRAG_TABLE_FULL, bỏ mảnh)
_add_fragment:
    fragment_count > max_fragments          → FRAG_TOO_MANY, bỏ cả datagram
    offset + len > 65535 - IHL              → FRAG_TOO_LARGE, bỏ (ping of death)
    MF=1 mà len không chia hết cho 8        → FRAG_BAD_LENGTH
    MF=0: payload_length = offset + len     (khác lần trước → FRAG_BAD_LENGTH)
    offset 0: lưu header; len < header TCP(20) / UDP(8) / ICMP(8) → FRAG_TINY_FIRST (RFC 1858)
    buffer.write(offset, payload, policy)   → FRAG_OVERLAP_CONFLICT / FRAG_DUPLICATE / FRAG_OVERLAP
đủ dữ liệu (có header, biết payload_length, [0, payload_length) liền mạch):
    build_reassembled_frame: header của mảnh đầu, total_length mới, xoá MF và offset (giữ DF),
    tính lại checksum → DefragOutput(fragment_count = N)
```

Mỗi `sweep_interval` (1s), `expire()` bỏ các datagram có mảnh đầu tiên đã quá `timeout` (30s), báo `FRAG_TIMEOUT` kèm chi tiết (`first fragment missing`, `last fragment missing`, hoặc `missing bytes 16-32`). `flush()` làm việc tương tự khi hết capture.

### 3.4 Bảng bất thường

| Tên | Ý nghĩa | Mức độ |
|---|---|---|
| `FRAG_OVERLAP_CONFLICT` | Hai mảnh chồng nhau với nội dung khác nhau | **Cao**: né IDS hoặc teardrop |
| `FRAG_TINY_FIRST` | Mảnh đầu không chứa đủ header transport | **Cao**: tiny fragment attack (RFC 1858), giấu cờ / port |
| `FRAG_BAD_LENGTH` | Mảnh giữa không chia hết cho 8, có hai "mảnh cuối" khác nhau, hoặc dữ liệu vượt quá mảnh cuối | Cao |
| `FRAG_TOO_LARGE` | Datagram ghép lại > 65535 byte | Cao (ping of death) |
| `FRAG_TOO_MANY` / `FRAG_TABLE_FULL` | Vượt giới hạn tài nguyên | Trung bình: có thể là DoS vào IDS |
| `FRAG_DUPLICATE` / `FRAG_OVERLAP` | Mảnh lặp hoặc chồng nhưng cùng nội dung | Thấp |
| `FRAG_TIMEOUT` | Datagram không bao giờ đủ mảnh | Trung bình |

### 3.5 API

`IpDefragmenter(timeout=30, overlap_policy="first", max_datagrams=1024, max_fragments=64, sweep_interval=1, on_anomaly=None)`

| Phương thức | Ý nghĩa |
|---|---|
| `process(ts, raw, capture_length, wire_length) -> DefragOutput \| None` | `None` khi đang chờ thêm mảnh |
| `expire(ts) -> int` | Bỏ các datagram quá hạn |
| `flush(ts=None) -> int` | Hết capture |
| `statistics()`, `anomaly_counts` | `frames`, `fragments`, `reassembled`, `dropped`, `pending`; số lần mỗi loại bất thường |

Hàm phụ: `ipv4_checksum`, `ip_to_text`, `build_reassembled_frame`.

---

## 4. `tcp_reassembly.py` – ráp stream TCP

### 4.1 Offset và wraparound

Mỗi chiều có một `base_seq`, là seq của byte dữ liệu đầu tiên:
- SYN có seq `x` → `base = x + 1` (SYN chiếm 1 số thứ tự).
- Không thấy SYN (bắt giữa chừng) → `base` = seq của segment có dữ liệu đầu tiên.

`seq_offset(seq, base)` tính khoảng cách **có dấu** trong không gian 32-bit:

```
((seq - base + 2^31) mod 2^32) - 2^31
```

Nhờ vậy seq vượt qua 2^32 rồi quay về 0 vẫn được xếp đúng (xem test `tcp_seq_wraparound`).

### 4.2 `StreamDirection`

- `data`: các byte `[0, next_offset)` đã liền mạch (tối đa `max_stream_bytes` = 1 MiB).
- `pending`: một `SparseBuffer` chứa dữ liệu đến sớm. Offset 0 của nó tương ứng với `next_offset`.
- Bộ đếm: `segments`, `bytes_seen`, `out_of_order_segments`, `retransmitted_bytes`, `overlap_bytes`, `conflict_bytes`, `dropped_bytes`.
- `anomalies`, và `unassembled` (các đoạn bị kẹt sau một lỗ khi kết nối đóng).

**`add_segment(seq, payload)`**:

```
offset = seq_offset(seq, base); end = offset + len
end ≤ 0                    → TCP_OLD_DATA (toàn bộ nằm trước điểm bắt đầu stream), bỏ
offset < 0                 → cắt phần trước điểm bắt đầu, TCP_OLD_DATA
offset < next_offset       → phần đã ráp rồi: TCP_RETRANSMISSION; so với data,
                             khác byte nào → TCP_OVERLAP_CONFLICT; chỉ giữ phần mới
rel = offset - next_offset
rel + len > max_window     → TCP_OUT_OF_WINDOW, bỏ
rel > 0                    → TCP_OUT_OF_ORDER
pending.write(rel, payload, policy) → TCP_OVERLAP / TCP_OVERLAP_CONFLICT
n = pending.contiguous_end(0); n > 0 → pop_front(n), next_offset += n, lưu vào data, trả n byte này
```

Bài tập trong `doc_for_phase.md` ("UNI", "ON SE", "LECT" gửi sai thứ tự → "UNION SELECT") chính là test `test_out_of_order_union_select`.

**Overlap với dữ liệu đã giao.** Byte đã chuyển sang `data` đã được đưa cho tầng sau (`on_data`), nên **không bao giờ bị sửa**. Bản gửi lại mà khác nội dung chỉ bị báo `TCP_OVERLAP_CONFLICT`. Policy `first` / `last` chỉ áp dụng cho dữ liệu còn nằm trong `pending` (chưa liền mạch). Kịch bản `tcp_overlap_conflict` minh hoạ điểm này.

### 4.3 `TcpReassembler`

| Phương thức | Hoạt động |
|---|---|
| `process(flow, packet, is_forward)` | Hook `on_packet`. Bỏ qua nếu không phải TCP. Lấy hoặc tạo `TcpStream`. Ghi `packet.defrag_anomalies` vào stream. Gặp SYN thì đặt `base`. Gói RST có payload → `TCP_RST_PAYLOAD`, bỏ (máy thật không giao payload của RST cho ứng dụng). Gọi `add_segment`; có byte mới thì gọi `on_data(stream, is_forward, chunk)` |
| `close_flow(flow)` | Hook `on_flow_end`. Kết thúc stream: byte kẹt sau lỗ → `TCP_GAP` + `unassembled`; rồi gọi `on_stream_end`. Nếu flow bị cắt bởi `ACTIVE_TIMEOUT` thì **lưu `next_seq`** của 2 chiều, để flow tiếp nối ráp tiếp đúng vị trí (test `test_hooks_and_active_timeout_continuation`) |
| `_stream_for(flow)` | Stream được tra theo `flow.key`. Nếu key trùng mà là **flow khác** (khi không nối `on_flow_end`) thì kết thúc stream cũ trước |
| `close_all()`, `statistics()`, `anomaly_counts` | |

`TcpStream` có `flow`, `client`, `server`, `closed`, và `context` (chỗ trống cho tầng sau dùng, ví dụ `context["http"]` là parser HTTP). Thuộc tính `suspicious` là `True` nếu stream có bất thường nằm trong `SUSPICIOUS_TCP_ANOMALIES`.

### 4.4 Bảng bất thường

| Tên | Bình thường hay khả nghi |
|---|---|
| `TCP_OUT_OF_ORDER`, `TCP_RETRANSMISSION`, `TCP_OVERLAP` (cùng nội dung) | Bình thường trên mạng thật (PCAP SSH thật có 2 lần retransmission) |
| `TCP_GAP`, `TCP_STREAM_TRUNCATED` | Bình thường (mất gói, hoặc stream lớn hơn 1 MiB) |
| `TCP_OVERLAP_CONFLICT` | **Khả nghi**: hai phiên bản khác nhau cho cùng một vị trí byte |
| `TCP_OLD_DATA` | **Khả nghi**: dữ liệu nằm trước điểm bắt đầu stream |
| `TCP_OUT_OF_WINDOW` | **Khả nghi**: seq ở quá xa phía trước (cũng là cách bảo vệ RAM) |
| `TCP_RST_PAYLOAD` | **Khả nghi**: dữ liệu giấu trong gói RST |
| `FRAG_OVERLAP_CONFLICT`, `FRAG_TINY_FIRST`, `FRAG_BAD_LENGTH` | **Khả nghi**: lấy từ `packet.defrag_anomalies` |

---

## 5. `http_normalizer.py` – chuẩn hoá và parser HTTP

### 5.1 Ba bản của URI và các rule tương ứng

| Trường | Cách tạo | Rule dùng (theo `flow_build_IDS.md`) |
|---|---|---|
| `uri_raw` | Nguyên văn | Bằng chứng trong alert |
| `uri_decoded` | Giải mã `%XX` / `%uXXXX` lặp lại (tối đa 3 lần); `+` → khoảng trắng chỉ trong query; gỡ overlong UTF-8; bỏ NUL; **giữ nguyên hoa/thường và comment** | SID 10005 (regex `union\s*/\*.*?\*/\s*select`) |
| `uri_normalized` | Từ `uri_decoded`: chuẩn hoá path (`\` → `/`, gộp `//`, xử lý `.` và `..`), giải mã HTML entity, bỏ comment SQL `/* */` (giữ phần thân của `/*!50000 ... */` vì MySQL vẫn chạy phần đó), chữ thường, gộp khoảng trắng | SID 10004 `union select`, 10006 `;cat ` / `/etc/passwd`, 10007 `<script` |
| `body_normalized` | Như trên. Nếu `Content-Type` là form-urlencoded thì giải mã URL trước | Rule trên body sau này |

Ví dụ thật lấy từ `results/http_encoding_evasion_verbose.txt`:

```
uri_raw        : /item.php?id=1%2527%2520UNION%2520SELECT%2520password
uri_decoded    : /item.php?id=1' UNION SELECT password            ← DOUBLE_ENCODING
uri_normalized : /item.php?id=1' union select password

uri_raw        : /static/..%2f..%2f..%c0%afetc/passwd
uri_decoded    : /static/../../../etc/passwd                      ← OVERLONG_UTF8
uri_normalized : /etc/passwd                                      ← PATH_TRAVERSAL
```

### 5.2 Các hàm chuẩn hoá

| Hàm | Hoạt động |
|---|---|
| `percent_decode_once(data, plus_as_space)` | Regex `%(?:[uU]XXXX\|XX)` → byte. Báo `UNICODE_ENCODING` (dạng `%u` của IIS) và `INVALID_PERCENT_ENCODING` (`%zz`) |
| `decode_repeatedly(data, max_rounds=3, plus_as_space)` | Giải mã đến khi không còn thay đổi. Từ 2 vòng trở lên → `DOUBLE_ENCODING`; vẫn còn đổi sau 3 vòng → `EXCESSIVE_ENCODING`. `+` chỉ đổi thành khoảng trắng ở vòng 1, nên `%2B` vẫn ra `+` |
| `bytes_to_text(data)` | Bỏ `\x00` (`NULL_BYTE`). Gỡ overlong UTF-8 (`\xc0\xaf` → `/`, `OVERLONG_UTF8`). Decode UTF-8; nếu lỗi thì dùng latin-1 (`INVALID_UTF8`) |
| `normalize_path(path)` | Xử lý path như web server. Có `..` → `PATH_TRAVERSAL`, và không bao giờ đi lên quá thư mục gốc |
| `strip_sql_comments(text)` | Quét tuyến tính bằng `str.find`. **Không dùng regex `.*?`**, vì với hàng trăm nghìn `/*` không đóng, regex sẽ chạy O(n²) (ReDoS làm treo IDS). Test kiểm tra 400 KB chạy dưới 1 giây (đo được ≈0,06 s) |
| `normalize_text(text)` | HTML entity → bỏ comment → chữ thường → gộp khoảng trắng (`\s+` → 1 dấu cách, gồm cả tab và xuống dòng) |
| `normalize_payload(data, ...)` | Chuẩn hoá chung cho payload bất kỳ, trả `NormalizedPayload(raw, decoded, normalized, decode_rounds, anomalies)` |

### 5.3 `HttpStreamParser` – parser chạy tăng dần

- `feed(bytes)` trả các request vừa đủ dữ liệu. `finish()` trả request cuối còn dở (`HTTP_INCOMPLETE`).
- Stream không bắt đầu bằng một method HTTP (ví dụ SSH) thì đặt `is_http=False` và bỏ qua.
- `parse_request_line`: URI là **mọi thứ giữa method và token `HTTP/x` cuối cùng**. Nhờ vậy `GET /p?id=1 UNION SELECT 1 HTTP/1.1` (đúng ví dụ ở RULE 4 trong roadmap) vẫn giữ đủ URI, kèm bất thường `HTTP_URI_SPACE`. Bản đầu tiên tôi viết tách theo khoảng trắng nên làm mất phần payload; test `test_sid_10004_union_select_variants` đã bắt được lỗi này.
- Body: đọc theo `Content-Length`, hoặc `Transfer-Encoding: chunked` (`decode_chunked`).
- Bất thường kiểu request smuggling: `HTTP_CONFLICTING_LENGTH` (hai Content-Length khác nhau), `HTTP_AMBIGUOUS_LENGTH` (có cả CL lẫn TE).
- Header quá 64 KB → `HTTP_HEADER_TOO_LONG` và dừng parse. Chunk sai định dạng → `HTTP_BAD_CHUNK`.
- `HttpRequest` có thêm `offset` (vị trí trong stream), `headers` (giữ nguyên thứ tự, kể cả header trùng) và `header(name)`.

---

## 6. `anti_evasion.py` – pipeline và CLI

`AntiEvasionPipeline(flow_timeout, active_timeout, fragment_timeout, overlap_policy, max_stream_bytes, on_defrag_event, on_stream_end, on_packet, on_http_request)`:

> Cập nhật Phase 5: thêm hai hook `on_packet(flow, packet, is_forward)` (gọi sau khi `TcpReassembler` đã xử lý gói) và `on_http_request(stream, request)` (gọi ngay khi một request đủ dữ liệu), và trường `HttpRequest.body_decoded` (body đã URL-decode nhưng còn giữ hoa/thường và comment, cho rule regex). Cả ba đều tùy chọn, hành vi cũ giữ nguyên.

| Phương thức | Hoạt động |
|---|---|
| `process_frame(ts, raw, caplen, wirelen)` | defrag → decode → gắn `reassembled_fragments` / `defrag_anomalies` vào Packet → `flow_manager.add_packet` (các hook lo phần còn lại) |
| `run_pcap(filename, limit)` | Đọc PCAP bằng `read_pcap_packets` của Phase 2 |
| `finish()` | `defragmenter.flush()` → `flow_manager.close_all()` (đóng stream qua hook) → `reassembler.close_all()` |
| `_on_stream_data` | Dữ liệu chiều client → server được đưa vào `HttpStreamParser` lưu trong `stream.context["http"]` |
| `_on_stream_end` | `parser.finish()`, rồi gọi callback của người dùng |

Hàm phụ: `stream_requests(stream)` lấy danh sách request; `preview(bytes)` hiển thị byte dễ đọc.

```bash
python "ids/phase 4/anti_evasion.py" <file.pcap> --mode verbose --result out.txt [--overlap-policy first|last] [--timeout 60] [-n 1000]
```

| Mode | Nội dung |
|---|---|
| quiet | Chỉ lỗi |
| normal | Bất thường defrag (WARNING), **chỉ các stream khả nghi**, thống kê |
| verbose | Mọi stream TCP: tóm tắt flow, thống kê ráp từng chiều, từng request HTTP với 3 bản URI |
| debug | Thêm header HTTP, nội dung stream đã ráp (`client data:` / `server data:`), đoạn chưa ráp được |

### Cách đọc một khối kết quả

```
Stream #1 [SUSPICIOUS]: TCP 192.168.10.20:40001 -> 192.168.10.30:80 ... conn_state=SF ...   ← tóm tắt Flow (Phase 3)
  client->server: assembled=80 segments=4 out_of_order=2 retransmitted=0 overlap=15 conflict=15 ...
                  anomalies=TCP_OUT_OF_ORDER:2,TCP_OVERLAP:1,TCP_OVERLAP_CONFLICT:1         ← ráp stream (Phase 4)
  HTTP request #1 (stream offset 0): GET /index.php?id=1+aaaa... HTTP/1.1
    uri_raw / uri_decoded / uri_normalized / decode_rounds / anomalies                    ← chuẩn hoá (Phase 4)
...
IP defrag: frames=.. fragments=.. reassembled=.. dropped=.. anomalies={..}               ← thống kê cuối file
TCP reassembly: streams=.. bytes_assembled=.. anomalies={..}
HTTP normalization: requests=.. anomalies={..}
```

---

## 7. Test và kết quả

Chạy: `.venv/Scripts/python -m unittest discover -s "tests/phase 4"` → **94/94 pass** (khoảng 8 giây). Phase 2 (4) và Phase 3 (36) vẫn pass.

| File test | Số test | Nội dung |
|---|---|---|
| `test_sparse_buffer.py` | 7 | ranges / gaps, policy first / last, overlap cùng nội dung, `pop_front`, byte 0 |
| `test_ip_defrag.py` | 18 | Frame không phải mảnh đi thẳng; ghép đúng thứ tự / ngược / xen kẽ 2 datagram; duplicate; overlap conflict (first vs last); tiny fragment; độ dài sai; VLAN; quá lớn; timeout; flush; bảng đầy; quá nhiều mảnh |
| `test_tcp_reassembly.py` | 24 | Wraparound; UNI / ON SE / LECT; retransmission giống / khác; overlap một phần; policy first / last; dữ liệu cũ; ngoài window; gap; giới hạn độ sâu; midstream; SYN mang data; payload trong RST; hook với FlowManager thật và flow tiếp nối khi active timeout |
| `test_http_normalizer.py` | 31 | Giải mã (double, `%u`, overlong, NUL, `%zz`, `+`); path; comment SQL và MySQL; ReDoS; HTML entity; **các buffer khớp đúng rule SID 10004–10007** với nhiều biến thể né tránh; URI có khoảng trắng; parser (pipeline, nạp từng byte, form, chunked, chưa đủ dữ liệu, không phải HTTP, smuggling, header quá dài) |
| `test_anti_evasion.py` | 14 | Chạy CLI trên 7 PCAP tấn công tự sinh và 3 PCAP BENIGN thật, ghi kết quả vào `results/`; gọi API pipeline trực tiếp |

### 7.1 Các PCAP tấn công (`tests/phase 4/pcaps/`, sinh bởi `pcap_factory.py`, mở được bằng Wireshark)

| PCAP | Kỹ thuật né | Kết quả mong đợi (đã đạt) |
|---|---|---|
| `tcp_out_of_order_sqli` | SQLi chia 3 segment, gửi theo thứ tự 1, 3, 2 | Ráp đúng; `uri_normalized` chứa `union select password from users` |
| `tcp_overlap_conflict` | Hai phiên bản cho byte 20–35 (mồi `aaaa…` và `UNION+SELECT`) | Luôn `TCP_OVERLAP_CONFLICT` + `[SUSPICIOUS]`. Policy `first` giữ bản mồi; policy `last` thấy `union select user,pass from users` |
| `tcp_retransmission` | Gửi lại cùng dữ liệu (lưu lượng bình thường) | `TCP_RETRANSMISSION:2`, **không** bị đánh dấu khả nghi |
| `tcp_seq_wraparound` | ISN = 2^32 − 10, seq quay vòng giữa request | `/wrap?x=<script>` ráp đúng |
| `ip_fragment_xss` | Segment TCP chứa XSS bị cắt thành 5 mảnh IP, gửi ngược thứ tự | `reassembled=1`, `fragments=5`, `<script>alert(document.cookie)</script>` |
| `ip_fragment_attacks` | Mảnh chồng khác nội dung, tiny fragment, datagram thiếu mảnh | `FRAG_OVERLAP_CONFLICT`, `FRAG_TINY_FIRST`, `FRAG_TIMEOUT … missing bytes 16-32`; stream TCP ghép từ tiny fragment bị `[SUSPICIOUS]` |
| `http_encoding_evasion` | Mã hoá kép, `/**/`, `%u`, `/*!50000*/`, `..%2f` + `%c0%af`, `;cat+`, body chunked | Tất cả chuẩn hoá về dạng rule match được (xem mục 5.1) |

### 7.2 File kết quả (`tests/phase 4/results/`)

| File | Đọc để thấy |
|---|---|
| `tcp_out_of_order_sqli_verbose.txt` / `_debug.txt` / `_normal.txt` | Ráp segment sai thứ tự. Bản debug có nội dung stream; bản normal không có stream nào (không khả nghi) |
| `tcp_overlap_conflict_verbose.txt` / `_normal.txt` / `_policy_last_verbose.txt` | So sánh policy first và last |
| `tcp_retransmission_verbose.txt` | Retransmission bình thường không bị báo động nhầm |
| `tcp_seq_wraparound_verbose.txt` | Seq quay vòng |
| `ip_fragment_xss_verbose.txt` / `_quiet.txt` | Ghép mảnh IP rồi giải mã XSS |
| `ip_fragment_attacks_verbose.txt` | Các dòng `WARNING: IP defrag anomaly` |
| `http_encoding_evasion_verbose.txt` | 6 request với 3 bản URI mỗi request |
| `BENIGN/{HTTP,SSH,ICMP}/*_anti_evasion_{normal,verbose}.txt` | Lưu lượng thật: HTTP ra 4 request, SSH ráp khoảng 23 KB với 2 lần retransmission. **Không có `[SUSPICIOUS]` nào** (không báo động nhầm) |

> `results/` nằm trong `.gitignore` (quy tắc `*results*/`, giống Phase 3), nên muốn có file thì chạy lại test. Còn `pcaps/` thì được commit bình thường.

---

## 8. Giới hạn và hướng phát triển

| # | Giới hạn | Đề xuất |
|---|---|---|
| 1 | Overlap policy áp dụng **chung cho mọi host** | Target-based: chọn policy theo hệ điều hành của máy đích (như frag3 / stream5 của Snort) |
| 2 | Byte đã giao cho tầng sau thì không đổi được nữa, nên nếu bản đúng đến sau thì chỉ có cảnh báo | Có thể giữ lại một "cửa sổ trễ" trước khi giao byte, hoặc chạy rule trên cả hai phiên bản khi có conflict |
| 3 | Chưa kiểm tra checksum hay TTL. Gói sai checksum hoặc TTL thấp (không đến được đích) vẫn được ráp vào stream, đây là kỹ thuật chèn dữ liệu giả kinh điển | Phase 2 thêm `checksum_valid`; Phase 4 bỏ qua segment sai checksum |
| 4 | Mới parse **request** HTTP; chưa parse response, gzip, `Content-Encoding` | Thêm khi có rule cần đến |
| 5 | Header (Cookie, User-Agent) được giữ nguyên, chưa chuẩn hoá | Thêm `header_normalized` nếu rule cần |
| 6 | UDP không được ráp (DNS dùng một datagram nên chưa cần) | Rule DNS tunneling (SID 10010) đọc thẳng payload UDP |
| 7 | HTTPS / TLS không đọc được nội dung | Ngoài phạm vi (cần giải mã TLS) |
| 8 | Viết bằng Python thuần nên hiệu năng có giới hạn | Đo ở Phase 11, rồi tối ưu (tách tiến trình, C-extension) |
| 9 | Chỉ hỗ trợ IPv4 | Đúng phạm vi hiện tại |
