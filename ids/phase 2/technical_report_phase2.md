# Báo cáo kỹ thuật Phase 2 – Packet Capture & Packet Decoder

Cập nhật: 2026-10-06

| File | Vai trò |
|---|---|
| `ids/phase 2/packet_capture.py` | Bắt frame Ethernet thô từ card mạng (Linux, AF_PACKET) và ghi ra file PCAP |
| `ids/phase 2/packet_decoder/packet.py` | `Packet`: đối tượng chuẩn (contract) truyền giữa các phase |
| `ids/phase 2/packet_decoder/utils.py` | Hàm tiện ích: format MAC/IP/cờ TCP, preview payload, cấu hình log |
| `ids/phase 2/packet_decoder/decoder.py` | Đọc PCAP, decode Ethernet → IPv4 → TCP/UDP/ICMP, tạo `Packet` |
| `ids/phase 2/packet_decoder/__init__.py` | Export API: `Packet`, `PacketDecoder`, `decode_pcap`, `iter_decoded_packets`, `print_packet_objects` |
| `ids/phase 2/packet_decode.py` | CLI: decode một file PCAP và ghi kết quả ra file text |
| `tests/phase 2/test_packet_capture.py`, `test_packet_decode.py` | 4 test |

---

## 1. Vị trí trong hệ thống

```
Card mạng (promiscuous)
      │  frame Ethernet thô
      ▼
packet_capture.py ──► capture.pcap                     (Phase 2 – capture)
                          │
                          ▼
     read_pcap_packets()  (timestamp, raw bytes, caplen, wirelen)
                          │
                 [Phase 4: IpDefragmenter]              (ghép mảnh IP trên frame thô)
                          │
                          ▼
     PacketDecoder.decode_ethernet() ──► Packet         (Phase 2 – decode)
                          │
                          ▼
                 Phase 3 FlowManager → Phase 4 TCP reassembly → ...
```

Phase 2 có **hai nửa độc lập**, nối với nhau qua file PCAP:

- **Capture** chỉ ghi byte thô, không phân tích gì, để không làm chậm vòng bắt gói.
- **Decode** đọc PCAP và biến byte thô thành `Packet` có các trường đã đặt tên.

Nhờ tách như vậy, khi làm live capture sau này chỉ cần thay *nguồn* frame. Decoder giữ nguyên, vì nó nhận vào `(timestamp, raw bytes)` chứ không quan tâm byte đến từ file hay từ socket.

---

## 2. `packet_capture.py` – bắt gói

### 2.1 Hằng số

| Tên | Giá trị | Ý nghĩa |
|---|---|---|
| `DEFAULT_INTERFACE` | `enp0s3` | Interface mặc định (VirtualBox) |
| `DEFAULT_OUTPUT` | `capture.pcap` | File ra mặc định |
| `DEFAULT_SNAPLEN` | 65535 | Số byte tối đa lưu cho mỗi frame |
| `PCAP_MAGIC` | `0xA1B2C3D4` | Magic number PCAP (độ chính xác micro giây) |
| `PCAP_VERSION_MAJOR/MINOR` | 2 / 4 | Phiên bản định dạng PCAP |
| `PCAP_LINKTYPE_ETHERNET` | 1 | Kiểu link layer: Ethernet |
| `ETH_P_ALL` | `0x0003` | Nhận mọi giao thức Ethernet (IPv4, IPv6, ARP, VLAN…) |

### 2.2 Định dạng PCAP được ghi

```
┌─────────────── Global header (24 byte, little-endian "<IHHIIII") ───────────────┐
│ magic 0xA1B2C3D4 │ major 2 │ minor 4 │ thiszone 0 │ sigfigs 0 │ snaplen │ linktype 1 │
└──────────────────────────────────────────────────────────────────────────────────┘
┌──── Record header (16 byte "<IIII") ────┐┌──── dữ liệu frame (incl_len byte) ────┐
│ ts_sec │ ts_usec │ incl_len │ orig_len  ││ Ethernet header + IP + ...             │
└──────────────────────────────────────────┘└────────────────────────────────────────┘
   ... lặp lại cho mỗi frame
```

Vì ghi bằng `<` (little-endian), 4 byte đầu của file là `d4 c3 b2 a1`.

### 2.3 Lớp `PcapWriter`

| Phương thức | Làm gì | Hoạt động thế nào |
|---|---|---|
| `__init__(filename)` | Mở file và ghi global header | Tạo thư mục cha nếu chưa có (`os.makedirs(..., exist_ok=True)`), mở file `wb`, `struct.pack("<IHHIIII", ...)`, rồi `flush()` |
| `write_packet(packet_data)` | Ghi một frame | Báo `ValueError` nếu frame dài hơn snaplen. Lấy `time.time()` tách thành giây + micro giây, ghi record header với `incl_len = orig_len = len(frame)`, ghi dữ liệu, rồi `flush()` |
| `close()` | Đóng file | |

### 2.4 Các hàm

| Hàm | Làm gì |
|---|---|
| `get_arguments()` | Đọc `-i/--interface` và `-o/--output` |
| `check_root()` | Thoát nếu không chạy bằng root (`os.geteuid() != 0`), vì raw socket cần quyền root |
| `check_interface(interface)` | `socket.if_nametoindex()`. Nếu interface không tồn tại thì in danh sách interface có sẵn rồi thoát |
| `print_available_interfaces()` | Liệt kê interface bằng `socket.if_nameindex()` |
| `print_banner(interface, output)` | In thông tin phiên capture |
| `capture_packets(interface, output)` | Vòng bắt gói chính (xem bên dưới) |

### 2.5 Vòng capture

1. Tạo socket `AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)`, nghĩa là nhận nguyên frame Ethernet của mọi giao thức.
2. `bind((interface, 0))` để chỉ nghe trên interface đã chọn.
3. Lặp vô hạn: `recvfrom(65535)` → đếm packet/byte → `PcapWriter.write_packet()` → in một dòng tóm tắt (`address[2]` là loại packet: host / broadcast / outgoing…).
4. Ctrl+C (`KeyboardInterrupt`) thì in thống kê. `PermissionError` / `OSError` thì in lỗi. Khối `finally` luôn đóng socket và file.

---

## 3. `packet_decoder/packet.py` – lớp `Packet`

`Packet` là **contract** giữa các phase. Phase 3, 4 và các phase sau chỉ đọc các trường này, không đọc dpkt trực tiếp.

| Nhóm | Trường | Ghi chú |
|---|---|---|
| Capture | `timestamp`, `capture_length`, `wire_length` | Lấy từ record header PCAP |
| Ethernet | `src_mac`, `dst_mac`, `ethertype` | |
| IPv4 | `src_ip`, `dst_ip`, `ip_protocol` (`"TCP"`/`"UDP"`/`"ICMP"`/`"OTHER(n)"`), `ip_protocol_number`, `ip_ttl`, `ip_id`, `ip_header_length`, `ip_total_length`, `ip_checksum`, `ip_options` | |
| Fragment | `fragment_offset` (đơn vị 8 byte), `fragment_offset_bytes`, `more_fragments`, `dont_fragment`, `ip_fragment_key = (src, dst, proto, ip_id)` | |
| **Do Phase 4 đặt** | `reassembled_fragments` (số mảnh đã ghép thành packet này), `defrag_anomalies` (tuple tên bất thường) | Mặc định `0` và `()`. Mới thêm khi viết Phase 4 |
| Port | `src_port`, `dst_port` | `None` với ICMP và với mảnh IP không phải mảnh đầu |
| TCP | `tcp_seq`, `tcp_ack`, `tcp_flags` (int), `tcp_flags_text`, `tcp_window`, `tcp_header_length`, `tcp_checksum`, `tcp_urgent_pointer`, `tcp_options` | |
| UDP | `udp_length`, `udp_checksum` | |
| ICMP | `icmp_type`, `icmp_code`, `icmp_checksum`, `icmp_identifier`, `icmp_sequence` | identifier/sequence chỉ có với Echo |
| Dữ liệu | `payload` (bytes của tầng ứng dụng), `flow_key` (5-tuple có hướng) | |

| Phương thức | Ý nghĩa |
|---|---|
| `payload_length()` | `len(payload)` |
| `is_ip_fragment()` | `fragment_offset != 0 or more_fragments` |
| `is_first_fragment()` | `fragment_offset == 0` |
| `summary()` | `TCP 1.2.3.4:5 -> 6.7.8.9:80 payload=12` |

---

## 4. `packet_decoder/utils.py`

| Hàm | Làm gì |
|---|---|
| `configure_logging(mode)` | `logging.basicConfig` với level theo mode: quiet = ERROR, normal/verbose = INFO, debug = DEBUG |
| `mac_to_string(mac)` | `b"\x02..."` → `"02:00:..."` |
| `ip_to_string(ip)` | `socket.inet_ntoa`; lỗi thì trả `"unknown"` |
| `format_tcp_flags(flags)` | `0x12` → `"SYN,ACK"` (theo bảng `TCP_FLAGS`) |
| `hex_preview(data, 64)` / `ascii_preview(data, 128)` | Xem trước payload dạng hex / ASCII (ký tự không in được thay bằng `.`) |
| `format_timestamp(ts)` | Epoch → `YYYY-MM-DD HH:MM:SS.ffffff` (UTC) |
| `protocol_name(number)` | 6 → `TCP`, 17 → `UDP`, 1 → `ICMP`, khác → `OTHER(n)` |

---

## 5. `packet_decoder/decoder.py`

### 5.1 `read_pcap_packets(file)` – đọc PCAP

Là một generator, yield ra `(timestamp, raw_bytes, incl_len, orig_len)`.

1. Đọc 24 byte global header. Nhận diện 4 magic để biết thứ tự byte và độ chính xác thời gian:

| Magic (byte đầu file) | Thứ tự byte | Độ chính xác |
|---|---|---|
| `d4 c3 b2 a1` | little-endian | micro giây |
| `a1 b2 c3 d4` | big-endian | micro giây |
| `4d 3c b2 a1` | little-endian | nano giây |
| `a1 b2 3c 4d` | big-endian | nano giây |

2. Lặp: đọc record header 16 byte, rồi đọc `incl_len` byte dữ liệu. `timestamp = ts_sec + ts_frac / (10^6 hoặc 10^9)`.
3. Header hoặc dữ liệu bị cắt cụt → `ValueError`. Hết file → dừng.

### 5.2 Lớp `PacketDecoder`

**Thuộc tính:**
- `output_mode`, `keep_packets`.
- Các bộ đếm: `total_packets`, `ipv4_packets`, `tcp_packets`, `udp_packets`, `icmp_packets`, `fragmented_packets`, `other_packets`, `decoded_packets`.
- `packets`: list các `Packet`, chỉ được điền khi `keep_packets=True`.

**Các phương thức decode** (gọi lần lượt theo tầng):

| Phương thức | Làm gì |
|---|---|
| `decode_ethernet(raw, timestamp, capture_length, wire_length)` | `dpkt.ethernet.Ethernet(raw)` (dpkt tự bóc VLAN 802.1Q). Frame lỗi thì log warning và trả `None`. Không phải IPv4 (ARP, IPv6…) thì `other_packets += 1` và trả `None`. Còn lại gọi `decode_ipv4` |
| `decode_ipv4(ip, ...)` | Lấy IP nguồn/đích, protocol, offset và cờ MF. Packet có `fragment_offset != 0` (mảnh không phải mảnh đầu) thì tạo `Packet` **không có port**, payload là byte thô. Còn lại, tuỳ `ip.data` là `dpkt.tcp.TCP` / `UDP` / `ICMP` mà gọi `decode_tcp` / `decode_udp` / `decode_icmp`. Protocol khác thì tạo `Packet` với payload thô |
| `decode_tcp(...)` | `flow_key = (src_ip, sport, dst_ip, dport, "TCP")`, payload = `tcp.data` |
| `decode_udp(...)` | Tương tự cho UDP |
| `decode_icmp(...)` | `flow_key = (src_ip, None, dst_ip, None, "ICMP")` |

**Các phương thức dựng `Packet`:**

| Phương thức | Làm gì |
|---|---|
| `build_packet(**data)` | Gộp `_ethernet_fields`, `_ipv4_fields`, `_transport_fields` thành một `Packet`. Tăng `decoded_packets`; chỉ thêm vào `self.packets` khi `keep_packets=True`; gọi `_log_packet` |
| `_ethernet_fields(eth)` | MAC và ethertype |
| `_ipv4_fields(ip, ...)` | Mọi trường IPv4 và fragment. `ip=None` thì để giá trị trống |
| `_transport_fields(tcp, udp, icmp)` | Dict đầy đủ các khoá, chỉ điền phần của protocol tương ứng. Với ICMP Echo thì lấy thêm `id` và `seq` |
| `_log_packet(packet)` | verbose: 1 dòng `summary()`. debug: in mọi trường theo từng tầng, kèm hex/ascii preview của payload |
| `print_statistics()` | Log dòng `Decoded packets: total=... objects=...` |

### 5.3 Các hàm cấp module

| Hàm | Làm gì |
|---|---|
| `iter_decoded_packets(filename, decoder, packet_limit)` | **API streaming** (Phase 3 dùng). Mở file, với mỗi frame thì `total_packets += 1`, `decode_ethernet`, và yield `Packet` nếu decode được. Dừng khi đạt `packet_limit`. Lỗi đọc file được ném ra cho nơi gọi xử lý |
| `decode_pcap(filename, packet_limit, output_mode)` | API kiểu cũ (batch). Tạo decoder với `keep_packets=True` và chạy hết generator. Bắt `FileNotFoundError`, `ValueError` và lỗi dpkt rồi ghi log. Cuối cùng in thống kê và trả về decoder |
| `print_packet_objects(decoder)` | Debug: in từng `Packet` đã lưu |

### 5.4 Ví dụ: một gói TCP đi qua decoder

```
raw: 02..1e 02..14 0800 | 45 00 0054 ... 06 ... c0a80a14 c0a80a1e | 9c40 0050 000003e9 ... 18 ... | "GET / ..."
      └─ Ethernet ─────┘  └──────────── IPv4 (20 byte) ───────────┘ └──── TCP (20 byte) ──────┘ └ payload ┘
 → Packet(src_ip="192.168.10.20", src_port=40000, dst_ip="192.168.10.30", dst_port=80,
          ip_protocol="TCP", tcp_seq=1001, tcp_flags=0x18 ("PSH,ACK"), payload=b"GET / ...")
```

---

## 6. `packet_decode.py` – CLI

```bash
python "ids/phase 2/packet_decode.py" data/BENIGN/ICMP/icmp_normal.pcap --mode debug --result out.txt -n 100
```

| Hàm | Làm gì |
|---|---|
| `get_arguments()` | `pcap`, `-n/--limit`, `--mode {quiet,normal,verbose,debug}`, `--result` |
| `_configure_result_logging(file, mode)` | Gắn `FileHandler` (UTF-8, ghi đè) vào root logger, đặt level theo mode, trả về những gì cần để khôi phục sau |
| `decode_pcap_to_file(...)` | Ghi phần đầu báo cáo, gọi `decode_pcap`. Khối `finally` gỡ handler và khôi phục level, để chạy nhiều lần trong cùng một tiến trình (test) không bị trùng log |
| `main()` | Đọc tham số rồi gọi hàm trên |

| Mode | Nội dung file kết quả |
|---|---|
| quiet | Chỉ lỗi |
| normal | Phần đầu báo cáo + thống kê |
| verbose | Thêm 1 dòng cho mỗi packet |
| debug | Thêm mọi trường theo từng tầng và preview payload |

---

## 7. Test

| Test | Kiểm tra |
|---|---|
| `test_writer_creates_readable_pcap` | File có độ dài 24 + 16 + n, magic `d4c3b2a1`, `incl_len = orig_len = n` |
| `test_writer_creates_nested_output_with_standard_global_header` | Tự tạo thư mục con (`WEB/XSS/xss.pcap`), global header đúng chuẩn |
| `test_writer_creates_valid_pcap_header` | File có ít nhất 24 byte và magic hợp lệ |
| `test_decode_capture_and_write_result` | Chạy CLI ở mode debug trên `data/BENIGN/ICMP/icmp_normal.pcap`; file kết quả phải có đủ các phần `capture:`, `ethernet:`, `ip:`, `tcp:`, `udp:`, `icmp:`, `flow:`, `payload:` và dòng thống kê |

File test decode còn có chế độ chạy tay: `python "tests/phase 2/test_packet_decode.py" --pcap <file> [--mode all]`, dùng để tạo kết quả cho cả 4 mode.

Chạy: `.venv/Scripts/python -m unittest discover -s "tests/phase 2"` → 4/4 pass.

---

## 8. Các thay đổi trong lúc làm Phase 3 và 4

1. `PacketDecoder(keep_packets=...)` cùng bộ đếm `decoded_packets`: decode theo kiểu streaming mà không giữ mọi `Packet` trong RAM.
2. `iter_decoded_packets(...)`: generator dùng cho pipeline streaming. `decode_pcap` giờ chạy bên trên generator này.
3. `Packet.reassembled_fragments`, `Packet.defrag_anomalies`: Phase 4 đặt giá trị sau khi ghép mảnh.

Cả 3 thay đổi đều tương thích ngược; test Phase 2 không phải sửa.

---

## 9. Giới hạn và đề xuất

| # | Vấn đề | Ảnh hưởng | Đề xuất |
|---|---|---|---|
| 1 | `read_pcap_packets` **không đọc trường linktype** (byte 20–23 của global header) mà luôn coi frame là Ethernet | Capture từ interface `any` của Linux (linktype 113, SLL) hoặc raw IP (101) sẽ bị decode sai mà không báo lỗi | Đọc linktype và báo lỗi (hoặc hỗ trợ SLL qua `dpkt.sll`) |
| 2 | Không hỗ trợ **pcapng** (định dạng mặc định của Wireshark mới) | File `.pcapng` báo "invalid PCAP magic" | Dùng `dpkt.pcapng.Reader`, hoặc yêu cầu lưu ở dạng `.pcap` |
| 3 | Decoder dùng `ip.off`, khiến dpkt in cảnh báo `IP.off is deprecated` ra stderr mỗi lần chạy, và thuộc tính này có thể bị xoá ở bản dpkt sau | Log rác; rủi ro hỏng khi nâng cấp dpkt | Dùng `ip.offset`, `ip.mf`, `ip.df` (dpkt 1.9.8 có sẵn) |
| 4 | Mảnh đầu (offset 0, có cờ MF) được dpkt parse thành TCP/UDP **từ dữ liệu bị cắt** | Port đúng nhưng payload và các trường phía sau có thể sai | Đã xử lý: Phase 4 ghép mảnh **trước** decoder, nên decoder chỉ còn thấy datagram hoàn chỉnh |
| 5 | Không kiểm tra **checksum** IP/TCP/UDP | Kỹ thuật né IDS: gửi gói sai checksum (host đích sẽ bỏ, nhưng IDS vẫn nhận) để chèn dữ liệu giả vào stream | Thêm cờ `checksum_valid` vào `Packet`, để Phase 4 bỏ qua segment sai checksum khi ráp stream |
| 6 | `PcapWriter.write_packet` lấy `time.time()` **lúc ghi**, không phải lúc kernel nhận gói | Timestamp lệch vài µs đến vài ms khi tải cao | Dùng `SO_TIMESTAMPNS` / ancillary data, hoặc libpcap |
| 7 | Capture `flush()` và `print()` cho **mỗi gói** | Không đạt mục tiêu 100.000 gói/giây trong `doc_for_phase.md` | Ghi theo lô, flush định kỳ, chỉ in thống kê theo chu kỳ |
| 8 | Chỉ decode IPv4 (IPv6 bị bỏ qua và đếm vào `other`) | Đúng phạm vi hiện tại | Khi làm IPv6 thì thêm `decode_ipv6` |
