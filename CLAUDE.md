# CLAUDE.md

File này cung cấp hướng dẫn cho Claude Code (claude.ai/code) khi làm việc với mã nguồn trong repository này.

## Dự án

Một hệ thống IDS mạng tự xây dựng từ đầu bằng Python, được phát triển theo từng phase đánh số. Pipeline mục tiêu (xem `flow for build/flow_build_IDS.md`) là:

> Capture → Decode → Flow → Reassembly → Normalization → Detection → Alert → SIEM

Hiện đã có phase 2–5 (capture/decode, theo dõi flow, chống né tránh, rule engine/detection). Các ghi chú thiết kế, báo cáo và phần lớn tài liệu được viết bằng tiếng Việt. Thư viện bên thứ ba: `dpkt` và `PyYAML` (cho rule YAML của phase 5), xem `requirements.txt`.

## Môi trường và lệnh

Có hai virtualenv: `.venv` (Windows, `.venv\Scripts\python.exe`) và `.venv-wsl` (Linux/WSL). Capture trực tiếp (`packet_capture.py`) dùng raw socket `AF_PACKET`, nên cần Linux và quyền root. Mọi thứ khác chạy offline trên file PCAP và hoạt động được trên Windows.

Tên thư mục có chứa dấu cách (`ids/phase 2`, `tests/phase 4`), nên luôn đặt đường dẫn trong dấu ngoặc kép.

```powershell
# Chạy toàn bộ test của một phase (từ thư mục gốc repo)
.\.venv\Scripts\python.exe -m unittest discover -s "tests/phase 4"

# Chạy một class hoặc method test (mọi file test đều gọi unittest.main())
.\.venv\Scripts\python.exe "tests/phase 3/test_flow_manager.py" TimeoutTests
.\.venv\Scripts\python.exe "tests/phase 3/test_flow_manager.py" TimeoutTests.test_name

# Helper decode của phase 2: ghi báo cáo cho mọi output mode, mô phỏng cấu trúc data/ trong tests/phase 2/results_decode/
.\.venv\Scripts\python.exe "tests/phase 2/test_packet_decode.py" --pcap "data/BENIGN/ICMP/icmp_normal.pcap"

# Chạy CLI của từng giai đoạn trên một file PCAP
python "ids/phase 2/packet_decode.py"  <pcap> --mode {quiet,normal,verbose,debug} --result out.txt
python "ids/phase 3/flow_manager.py"   <pcap> --mode verbose [--timeout S] [--active-timeout S]
python "ids/phase 4/anti_evasion.py"   <pcap> --mode verbose [--overlap-policy first|last]
python "ids/phase 5/rule_engine.py"    <pcap> --mode verbose [--alerts alerts.jsonl] [--enable SID] [--disable SID] [--rules DIR]
python "ids/phase 5/rule_engine.py"    --list-rules          # kiểm tra (validate) và liệt kê rule
sudo python3 "ids/phase 2/packet_capture.py" -i enp0s3 -o capture.pcap   # Chỉ trên Linux

# Đối chiếu các PCAP thật trong data/ với ground truth (bỏ qua PCAP rỗng), tổng hợp ở tests/phase 5/results/dataset/summary.txt
.\.venv\Scripts\python.exe "tests/phase 5/test_dataset.py"
```

Không có linter, bước build hay cấu hình đóng gói.

## Kiến trúc

### Cách nạp module
Các thư mục phase không phải là package. Mỗi module tự thêm các thư mục phase liên quan vào `sys.path` rồi import bằng tên module trần. Ví dụ, `flow_manager.py` thêm `ids/phase 2`, `anti_evasion.py` thêm phase 2 và 3, và mỗi file test thêm các thư mục phase mà nó cần. Hãy làm theo cùng mẫu này cho các phase mới (ví dụ `from flow_manager import FlowManager`, `from packet_decoder import PacketDecoder`).

### Pipeline xử lý dạng luồng (được nối trong `ids/phase 4/anti_evasion.py`, `AntiEvasionPipeline`)
```
raw frame → IpDefragmenter → PacketDecoder.decode_ethernet → FlowManager.add_packet
              (phase 4)          (phase 2)                       (phase 3)
                                                      on_packet ↓        ↓ on_flow_end
                                           TcpReassembler.process   TcpReassembler.close_flow
                                                      on_data ↓
                                           HttpStreamParser (mỗi stream một parser, lưu trong stream.context["http"])
```
- Xử lý từng gói một, các giai đoạn nối với nhau bằng callback. `AntiEvasionPipeline` có các hook `on_packet(flow, packet, is_forward)`, `on_http_request(stream, request)` và `on_stream_end(stream)`; tầng sau gắn vào đó thay vì đệm toàn bộ capture.
- **Phase 2** `packet_decoder/`: `PacketDecoder` chuyển raw Ethernet frame thành dataclass `Packet` (5-tuple, flags, payload). `read_pcap_packets` trả về các raw frame, còn `iter_decoded_packets` kết hợp đọc và decode.
- **Phase 3** `flow_manager.py`: flow hai chiều được định danh bằng 5-tuple chuẩn hóa, có đoán chiều client/server, máy trạng thái TCP, idle timeout theo từng giao thức (`FlowTimeouts`), active timeout để tách các flow dài, và các lần quét định kỳ dựa trên timestamp của gói tin (không dùng đồng hồ thực). Các IP fragment không phải fragment đầu mà đến được flow manager sẽ được đếm vào `ignored_fragments`, vì việc ghép fragment được kỳ vọng xảy ra ở bước trước.
- **Phase 4**: `sparse_buffer.SparseBuffer` (buffer định vị theo offset, theo dõi lỗ hổng dữ liệu, vùng chồng lấn và chồng lấn xung đột) được dùng chung bởi `ip_defrag` và `tcp_reassembly`. Overlap policy (`first`/`last`) quyết định bản dữ liệu chồng lấn nào được giữ. `http_normalizer` thực hiện percent-decode lặp lại, chuẩn hóa đường dẫn, loại bỏ comment SQL và decode chunked.
- Các anomaly là hằng chuỗi (`TCP_OVERLAP_CONFLICT`, `FRAG_TINY_FIRST`, ...). `tcp_reassembly.SUSPICIOUS_TCP_ANOMALIES` tách các dấu hiệu né tránh khỏi những anomaly vốn bình thường trên mạng thực.
- **Phase 5** (`rule_engine.DetectionPipeline` bọc `AntiEvasionPipeline`): `rule_loader` đọc `ids/phase 5/rules/*.yaml` (biến `$NAME`, validate schema, SID duy nhất, `supersedes`) thành `RuleSet`. `DetectionEngine` khớp rule trên 3 loại event: `packet` (protocol, threshold, dns_tunnel, content/regex trên `packet_payload`), `http` (content/regex trên các buffer `http_uri`, `http_uri_decoded`, ... của `HttpRequest`) và `scan` (`behavior.ScanTracker` gom probe theo cặp (src, dst) thành episode, đóng sau 10s im lặng, gán đúng một kỹ thuật `half_open`/`connect`/`service`). `ContentMatcher` hiện dùng `in`; Phase 6 thay ruột bằng Aho-Corasick mà giữ nguyên interface. Alert ghi ra JSON lines.

### Quy ước CLI
CLI của mỗi giai đoạn có cùng cấu trúc: `get_arguments()`, `main()`, và một hàm `analyze_pcap_to_file()`/`decode_pcap_to_file()` gắn tạm một `FileHandler` vào root logger để ghi báo cáo dạng text. Các output mode là `quiet`, `normal`, `verbose` và `debug`.

## Dữ liệu và kết quả test
- `data/{BENIGN,ANOMALY,RECON,WEB}/<TYPE>/*.pcap` là traffic thu được trong lab (Kali tấn công → Ubuntu IDS VM) và được test sử dụng. Mỗi thư mục có `scenario.md` mô tả kịch bản và kết quả mong đợi. `utilisation/` (ghi chú cài đặt lab), `flow for build/` và `nội dung project.md` (tài liệu thiết kế tổng thể) bị gitignore nên có thể không tồn tại trên máy khác.
- `dataset/` chứa bộ script sinh lại các PCAP này: `capture_dataset.sh` (chạy trên máy IDS, `tcpdump` + BPF) và `attack_runner.sh` (chạy trên máy generator Kali), dùng chung tên scenario (`./dataset/capture_dataset.sh list`). Cấu hình qua biến môi trường `IFACE`, `VICTIM`, `GENERATOR`, `HTTP_PORT`, `SSH_USER`, `STEP_DELAY`.
- `dataset/README.md` có bảng **ground truth**: mỗi scenario tấn công gắn với đúng một rule ID (10002–10004, 10006–10010) và severity; 4 scenario BENIGN là thước đo false positive và phải cho 0 alert. Bản sao dạng code nằm ở `tests/phase 5/ground_truth.py`.
- `tests/phase 4/pcap_factory.py` tạo các PCAP né tránh tổng hợp (TCP sai thứ tự và chồng lấn, quay vòng sequence number, tấn công IP fragment, né tránh bằng mã hóa HTTP) vào `tests/phase 4/pcaps/`. `tests/phase 5/scenario_factory.py` dùng lại các helper đó để mô phỏng 12 scenario của dataset (nmap -sS/-sT/-sV, curl, hping3, dig). Test ghi báo cáo dễ đọc vào các thư mục `results*/`, vốn bị gitignore.
- Mỗi phase có một file `technical_report_phaseN.md` mô tả các quyết định thiết kế. Hãy đọc file đó trước khi sửa phase tương ứng.
