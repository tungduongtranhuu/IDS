# CLAUDE.md

File này cung cấp hướng dẫn cho Claude Code (claude.ai/code) khi làm việc với mã nguồn trong repository này.

## Dự án

Một hệ thống IDS mạng tự xây dựng từ đầu bằng Python, được phát triển theo từng phase đánh số. Pipeline mục tiêu (xem `flow for build/flow_build_IDS.md`) là:

> Capture → Decode → Flow → Reassembly → Normalization → Detection → Alert → SIEM

Hiện đã có phase 2–4 (capture/decode, theo dõi flow, chống né tránh). Các ghi chú thiết kế, báo cáo và phần lớn tài liệu được viết bằng tiếng Việt. Thư viện bên thứ ba duy nhất là `dpkt` (`requirements.txt`).

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
sudo python3 "ids/phase 2/packet_capture.py" -i enp0s3 -o capture.pcap   # Chỉ trên Linux
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
- Xử lý từng gói một, các giai đoạn nối với nhau bằng callback. Phase tiếp theo (detection) nên gắn vào qua các hook này (`on_stream_end`, dict `context` của mỗi stream, và các đối tượng `HttpRequest` đã chuẩn hóa) thay vì đệm toàn bộ capture.
- **Phase 2** `packet_decoder/`: `PacketDecoder` chuyển raw Ethernet frame thành dataclass `Packet` (5-tuple, flags, payload). `read_pcap_packets` trả về các raw frame, còn `iter_decoded_packets` kết hợp đọc và decode.
- **Phase 3** `flow_manager.py`: flow hai chiều được định danh bằng 5-tuple chuẩn hóa, có đoán chiều client/server, máy trạng thái TCP, idle timeout theo từng giao thức (`FlowTimeouts`), active timeout để tách các flow dài, và các lần quét định kỳ dựa trên timestamp của gói tin (không dùng đồng hồ thực). Các IP fragment không phải fragment đầu mà đến được flow manager sẽ được đếm vào `ignored_fragments`, vì việc ghép fragment được kỳ vọng xảy ra ở bước trước.
- **Phase 4**: `sparse_buffer.SparseBuffer` (buffer định vị theo offset, theo dõi lỗ hổng dữ liệu, vùng chồng lấn và chồng lấn xung đột) được dùng chung bởi `ip_defrag` và `tcp_reassembly`. Overlap policy (`first`/`last`) quyết định bản dữ liệu chồng lấn nào được giữ. `http_normalizer` thực hiện percent-decode lặp lại, chuẩn hóa đường dẫn, loại bỏ comment SQL và decode chunked.
- Các anomaly là hằng chuỗi (`TCP_OVERLAP_CONFLICT`, `FRAG_TINY_FIRST`, ...). `tcp_reassembly.SUSPICIOUS_TCP_ANOMALIES` tách các dấu hiệu né tránh khỏi những anomaly vốn bình thường trên mạng thực.

### Quy ước CLI
CLI của mỗi giai đoạn có cùng cấu trúc: `get_arguments()`, `main()`, và một hàm `analyze_pcap_to_file()`/`decode_pcap_to_file()` gắn tạm một `FileHandler` vào root logger để ghi báo cáo dạng text. Các output mode là `quiet`, `normal`, `verbose` và `debug`.

## Dữ liệu và kết quả test
- `data/{BENIGN,ANOMALY,RECON,WEB}/<TYPE>/*.pcap` là traffic thu được trong lab (Kali tấn công → Ubuntu IDS VM) và được test sử dụng. `utilisation/` (ghi chú cài đặt lab) bị gitignore.
- `tests/phase 4/pcap_factory.py` tạo các PCAP né tránh tổng hợp (TCP sai thứ tự và chồng lấn, quay vòng sequence number, tấn công IP fragment, né tránh bằng mã hóa HTTP) vào `tests/phase 4/pcaps/`. Test ghi báo cáo dễ đọc vào các thư mục `results*/`, vốn bị gitignore.
- Mỗi phase có một file `technical_report_phaseN.md` mô tả các quyết định thiết kế. Hãy đọc file đó trước khi sửa phase tương ứng.
