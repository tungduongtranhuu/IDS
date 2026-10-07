# Báo cáo kỹ thuật Phase 3 – Flow Manager

Cập nhật: 2026-10-06 (sau khi chuyển xử lý IP fragment sang Phase 4)

| File | Vai trò |
|---|---|
| `ids/phase 3/flow_manager.py` | Gom packet thành flow hai chiều, theo dõi state TCP, timeout, phát hook cho Phase 4 |
| `tests/phase 3/test_flow_manager.py` | 36 test (31 unit + 5 chạy CLI trên PCAP thật) |
| `ids/phase 3/report_phase3.md` | Nhật ký thay đổi: đã sửa gì, vì sao (không phải tài liệu kỹ thuật) |

---

## 1. Nhiệm vụ và ranh giới

**Phase 3 làm:**
- 5-tuple, flow table, flow hai chiều.
- Xác định client/server.
- State TCP và bộ đếm cờ.
- Timeout theo protocol và active timeout.
- Phát sự kiện cho các phase sau qua `on_packet` / `on_flow_end`.

**Phase 3 không làm** (thuộc Phase 4):
- Ghép mảnh IP.
- Ráp TCP stream theo seq.
- Normalization.

**Phase 3 không làm** (thuộc Phase 5 trở đi):
- Rule, cảnh báo.

```
raw frame → [Phase 4 IpDefragmenter] → PacketDecoder (Phase 2)
                                             │ Packet
                                             ▼
                                 FlowManager.add_packet()
                                   │                 │
               on_packet(flow, packet, is_forward)   on_flow_end(flow)
                                   ▼                 ▼
                    Phase 4 TcpReassembler       Phase 4 close stream / Phase 7 behavior
```

Phase 3 không giữ payload. Nó chỉ đếm số byte payload theo từng chiều.

---

## 2. Mô hình dữ liệu

### 2.1 Key

| Kiểu | Dạng | Dùng để |
|---|---|---|
| `DirectionalKey` | `(src_ip, src_port, dst_ip, dst_port, proto)` | Mô tả một packet, có hướng |
| `CanonicalKey` | `((ip, port), (ip, port), proto)`, 2 đầu được sắp xếp | Tra dict `flows`: hai chiều của cùng một kết nối cho ra cùng một key |
| `Endpoint` | `(ip, port)` | `flow.client`, `flow.server` |

Riêng ICMP: `packet_flow_key` đặt `icmp_identifier` vào cả hai ô port. Nhờ vậy mỗi phiên ping là một flow riêng.

### 2.2 `FlowTimeouts` (dataclass frozen)

| Trường | Mặc định | Áp dụng cho |
|---|---|---|
| `tcp_new` | 30s | TCP ở `NONE`, `SYN_SENT`, `SYN_RECEIVED` |
| `tcp_established` | 300s | TCP ở `ESTABLISHED`, `MIDSTREAM`, `FIN_WAIT` |
| `tcp_closing` | 5s | TCP ở `CLOSING` (cả hai bên đã FIN) |
| `tcp_closed` | 2s | TCP ở `CLOSED` (đã RST) |
| `udp` / `icmp` / `other` | 60s / 30s / 60s | |

- `from_single_timeout(s)`: mọi loại dùng `s`, riêng `tcp_closing` / `tcp_closed` vẫn ngắn (`min(s, mặc định)`).
- `validate()`: báo lỗi nếu có timeout ≤ 0.
- `idle_timeout(flow)`: chọn giá trị theo protocol và `tcp_state`.

### 2.3 `Flow` (dataclass)

| Nhóm | Trường |
|---|---|
| Định danh | `key`, `protocol`, `client`, `server`, `first_seen`, `last_seen`, `is_continuation` |
| Thống kê | `packet_count`, `byte_count`, `payload_byte_count`, `fwd_packets`, `bwd_packets`, `fwd_bytes`, `bwd_bytes`, `fwd_payload_bytes`, `bwd_payload_bytes`, `fragment_count` |
| TCP | `tcp_state`, `tcp_flag_counts`, `history`, `client_isn`, `syn_seen`, `synack_seen`, `handshake_completed`, `fwd_fin`, `bwd_fin`, `fwd_rst`, `bwd_rst`, `packets_after_rst` |
| Kết thúc | `status` (`ACTIVE` / `EXPIRED` / `CLOSED`), `termination_reason` |
| Debug | `packets` (chỉ có khi `store_packets=True`) |

"fwd" là client → server, "bwd" là server → client. `fragment_count` cộng dồn `packet.reassembled_fragments` do Phase 4 đặt.

---

## 3. Thuật toán

### 3.1 Xử lý một packet: `FlowManager.add_packet(packet)`

```
_advance_clock(ts)                         clock = max(clock, ts)
nếu là mảnh không phải mảnh đầu (offset ≠ 0):
    ignored_fragments += 1, trả None       (bình thường Phase 4 đã ghép xong trước đó)
ngược lại _add_regular_packet:
    dkey = packet_flow_key(packet); ckey = canonical_flow_key(dkey)
    flow = flows.get(ckey)
    nếu có flow → _ending_before_packet(flow, packet):
         1. ts - last_seen  ≥ idle_timeout(flow)  → kết thúc (TIMEOUT / TCP_FIN / TCP_RST)
         2. ts - first_seen ≥ active_timeout      → kết thúc ACTIVE_TIMEOUT (sẽ có flow tiếp nối)
         3. _is_new_tcp_connection                → kết thúc (TCP_PORT_REUSE / TCP_FIN / TCP_RST)
    nếu không còn flow → _create_flow (guess_client, hoặc kế thừa nếu là flow tiếp nối)
    is_forward = (src_ip, src_port) == flow.client
    _assign → flow.add_packet → cộng tổng → on_packet(flow, packet, is_forward)
_maybe_sweep()                             expire() nếu đã qua ≥ sweep_interval
```

Thứ tự hook luôn là: `on_flow_end(flow cũ)` **trước** `on_packet(flow mới, ...)`.

### 3.2 Xác định client: `guess_client(packet, dkey)`

1. TCP SYN (không có ACK) → người gửi là client. SYN-ACK → người **nhận** là client.
2. ICMP reply (type 0/14/16/18) → người nhận là client. Các type khác → người gửi là client.
3. Còn lại (UDP, TCP bắt giữa chừng) → bên có **port thấp hơn** là server.

### 3.3 Máy trạng thái TCP: `Flow._update_tcp`

```
             SYN (client)            SYN-ACK (server)          ACK (client)
   NONE ───────────────► SYN_SENT ───────────────► SYN_RECEIVED ───────────► ESTABLISHED
    │                                                                         │
    │ packet đầu không phải SYN / SYN-ACK                                     │ FIN 1 bên
    └──────────► MIDSTREAM                                                    ▼
                                                                          FIN_WAIT ──FIN bên kia──► CLOSING
   Bất kỳ state nào ──RST──► CLOSED      (packet đến sau RST: packets_after_rst += 1)
```

Ngoài state, hàm còn ghi lại:
- `tcp_flag_counts`: SYN, FIN, RST, PSH, ACK, URG, ECE, CWR, và `NULL` (packet không có cờ nào).
- `history` kiểu Zeek: chữ hoa là từ client, chữ thường là từ server. `S` SYN, `H` SYN-ACK, `A` ACK thuần, `D` có data, `F` FIN, `R` RST. Mỗi chữ chỉ ghi lần đầu xuất hiện.
- `client_isn`: seq của SYN đầu tiên, dùng để nhận ra port bị dùng lại.

**Nhận ra kết nối mới** (`_is_new_tcp_connection`): packet là SYN không có ACK, **và** một trong hai điều kiện sau:
- flow đang `FIN_WAIT` / `CLOSING` / `CLOSED`;
- flow đang `ESTABLISHED` / `MIDSTREAM` nhưng seq khác `client_isn`.

SYN gửi lại khi đang `SYN_SENT` vẫn thuộc cùng flow.

### 3.4 `conn_state` (tóm tắt kiểu Zeek)

| Giá trị | Điều kiện |
|---|---|
| `S0` | Có SYN, không có trả lời |
| `REJ` | SYN → server RST |
| `RSTOS0` / `SH` | Client gửi SYN rồi RST / FIN, không có SYN-ACK |
| `RSTRH` / `SHR` | Chỉ thấy SYN-ACK, rồi server RST / FIN |
| `S1` | Đã kết nối, chưa đóng |
| `SF` | Đóng bình thường (FIN cả hai bên) |
| `S2` / `S3` | Chỉ client / chỉ server gửi FIN |
| `RSTO` / `RSTR` | Đã kết nối, client / server gửi RST |
| `OTH` | Không thấy SYN |
| UDP / ICMP | `SF` nếu có cả hai chiều, `S0` nếu chỉ một chiều |

### 3.5 Hết hạn và kết thúc

- `expire(ts)`: quét mọi flow, flow nào `ts - last_seen ≥ idle_timeout` thì `_finish`. Được gọi tự động mỗi `sweep_interval` giây (tính theo thời gian của packet), nên chi phí là O(số flow × số lần quét) chứ không phải O(số flow × số packet). Khi chạy live, cần gọi bằng timer.
- **Active timeout** chỉ được kiểm tra khi có packet đến (`_ending_before_packet`), để flow tiếp nối được tạo ngay và kế thừa client/server cùng state TCP (`Flow.continue_from`).
- `_finish(flow, status, reason)`: xoá flow khỏi bảng → đặt status và reason → cộng `termination_counts` → lưu vào `expired_flows` nếu `keep_finished_flows=True` → gọi `on_flow_end`.
- `close_all()`: hết capture, đóng mọi flow còn lại với reason `END_OF_CAPTURE`.

| `termination_reason` | `status` | Khi nào |
|---|---|---|
| `TIMEOUT` | EXPIRED | Hết idle timeout |
| `ACTIVE_TIMEOUT` | EXPIRED | Flow quá dài, bị cắt |
| `TCP_FIN` | CLOSED | Đã `CLOSING` rồi hết `tcp_closing`, hoặc có SYN mới |
| `TCP_RST` | CLOSED | Đã `CLOSED` rồi hết `tcp_closed`, hoặc có SYN mới |
| `TCP_PORT_REUSE` | CLOSED | SYN mới trên flow đang `ESTABLISHED` / `MIDSTREAM` / `FIN_WAIT` |
| `END_OF_CAPTURE` | CLOSED | `close_all()` |

---

## 4. API

### 4.1 Hàm cấp module

| Hàm | Làm gì |
|---|---|
| `packet_flow_key(packet)` | Tạo 5-tuple có hướng (ICMP thì dùng identifier làm port) |
| `canonical_flow_key(dkey)` | Tạo key không phụ thuộc chiều (sắp 2 đầu theo `(str(ip), port hoặc -1)`) |
| `guess_client(packet, dkey)` | Trả `(client, server)` |
| `packet_size(packet)` | Byte tầng IP: lấy giá trị khác 0 đầu tiên trong `ip_total_length`, `wire_length`, `capture_length`, rồi mới đến `len(payload)` |
| `is_non_first_fragment(packet)` | `fragment_offset != 0` |
| `_format_endpoint(ep, proto)` | `ip:port`, hoặc `ip[id=N]` với ICMP |

### 4.2 `FlowManager(...)`

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `flow_timeout` | `None` | Một idle timeout cho mọi loại (không dùng chung với `timeouts`) |
| `timeouts` | `FlowTimeouts()` | Cấu hình timeout chi tiết |
| `active_timeout` | 120 | Thời lượng tối đa của một flow |
| `sweep_interval` | 1 | Khoảng cách giữa hai lần quét hết hạn |
| `store_packets` | False | Lưu `Packet` vào flow (chỉ để debug) |
| `keep_finished_flows` | False | Giữ flow đã xong trong `expired_flows` |
| `on_packet` | None | `(flow, packet, is_forward) -> None`, gọi sau mỗi packet |
| `on_flow_end` | None | `(flow) -> None`, gọi khi flow kết thúc |

| Phương thức / thuộc tính | Ý nghĩa |
|---|---|
| `add_packet(packet) -> Flow \| None` | Điểm vào chính |
| `expire(ts) -> list[Flow]` | Đóng các flow đã quá idle timeout tại thời điểm `ts` |
| `close_all() -> list[Flow]` | Đóng mọi flow còn lại |
| `statistics() -> dict` | `flows`, `active_flows`, `finished_flows`, `expired_flows`, `packets`, `bytes`, `ignored_fragments`, `sweeps` |
| `termination_counts` | Số flow theo từng lý do kết thúc |
| `flows`, `clock` | Bảng flow đang sống; đồng hồ (theo thời gian packet) |

Các phương thức nội bộ: `_advance_clock`, `_add_regular_packet`, `_ending_before_packet`, `_idle_ending`, `_is_new_tcp_connection`, `_create_flow`, `_assign`, `_maybe_sweep`, `_finish`. Hoạt động của chúng xem mục 3.

### 4.3 CLI

```bash
python "ids/phase 3/flow_manager.py" data/BENIGN/HTTP/http_normal.pcap --mode verbose --result out.txt [--timeout 60] [--active-timeout 300] [-n 1000]
```

`analyze_pcap_to_file` dùng `iter_decoded_packets` (streaming). Mỗi flow được ghi log ngay lúc kết thúc (`Flow #n: ...` ở mode verbose; mode debug in thêm từng packet). Cuối cùng ghi thống kê decoder, thống kê flow và các lý do kết thúc.

> CLI Phase 3 **không** ghép mảnh IP. Muốn xử lý capture có fragment thì dùng CLI Phase 4 (`ids/phase 4/anti_evasion.py`).

---

## 5. Test (36)

| Nhóm | Số test | Nội dung |
|---|---|---|
| `FlowLifecycleTests` | 7 | Ngắt quãng dài thì tạo flow mới; RST đóng sau 2s; SYN sau RST/FIN là flow mới; `packets_after_rst`; SYN gửi lại không tạo flow mới |
| `DirectionTests` | 4 | Client là bên gửi SYN; gặp SYN-ACK trước; heuristic port thấp; bộ đếm fwd/bwd |
| `TcpFlagTests` | 5 | `S0`, `REJ`, `RSTO` (SYN scan), `S1`, packet NULL |
| `MemoryTests` | 3 | Không giữ packet / flow / payload theo mặc định |
| `PacketHookTests` | 3 | Hook nhận đúng (flow, packet, chiều); thấy state đã cập nhật; thứ tự end → packet |
| `SweepTests` | 2 | Chỉ quét một lần mỗi interval; quét đóng các flow im lặng |
| `TimeoutTests` | 3 | Timeout theo protocol/state; active timeout giữ hướng; tham số sai bị từ chối |
| `FragmentIcmpSizeTests` | 4 | Mảnh rời bị bỏ qua và đếm; `reassembled_fragments` được cộng; ICMP identifier; byte count dùng `ip_total_length` |
| `FlowManagerTests` | 5 | `expire()` + chạy CLI ở 4 mode trên 3 PCAP BENIGN (kết quả ở `tests/phase 3/results/`) |

Chạy: `.venv/Scripts/python -m unittest discover -s "tests/phase 3"` → 36/36 pass.

---

## 6. Giới hạn

1. Chưa giới hạn tổng số flow (SYN flood tạo rất nhiều flow `S0`). Nên thêm `max_flows` và chế độ khẩn cấp (rút ngắn timeout khi bảng đầy), giống Suricata.
2. Heuristic "port thấp là server" có thể đoán sai khi cả hai đều là port tạm.
3. `canonical_flow_key` so sánh IP dạng chuỗi. Vẫn đúng và ổn định, nhưng khi thêm IPv6 nên chuyển sang `ipaddress`.
4. Detection theo **nhiều flow** (port scan: một IP tạo nhiều flow `S0`/`REJ`) chưa có. Việc này thuộc Behavior Engine (Phase 7), sẽ dùng `on_flow_end` cùng `conn_state`.
