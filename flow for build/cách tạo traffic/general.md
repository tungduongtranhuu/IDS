                    LAB TRAFFIC
                         │
             ┌───────────┴───────────┐
             │                       │
          BENIGN                 SUSPICIOUS
             │                       │
       HTTP / SSH / DNS        Scan / Web / Anomaly
             │                       │
             └───────────┬───────────┘
                         ↓
                  Ubuntu IDS
                         ↓
                  capture.pcap
                         ↓
                    Decoder
                         ↓
                     Flow
                         ↓
                  Reassembly
                         ↓
                  Normalization
                         ↓
                    Detection
                         ↓
                      Alert

Đây cũng khớp với pipeline bạn đã thiết kế: Capture → Decode → Flow → Reassembly → Normalization → Detection → Alert → SIEM.

1. Tôi khuyên bạn chia việc test thành 3 loại PCAP
Loại A — Benign PCAP

Trước tiên tạo traffic bình thường:

Kali
 │
 ├── ping Victim
 ├── mở HTTP
 ├── SSH login bình thường
 ├── DNS queries
 └── một số request HTTP bình thường
          │
          ↓
       IDS
          │
          ↓
    benign_01.pcap

Mục đích không phải để IDS “phát hiện” mà để kiểm tra:

IDS có xử lý traffic bình thường mà không sinh alert sai không?

Đây rất quan trọng khi bạn sau này đánh giá false positive.

2. Sau đó mới tự tạo suspicious traffic

Với project hiện tại, tôi sẽ không làm 10 loại cùng lúc.

File của bạn đã có thứ tự 10 rule khá rõ ràng, bắt đầu từ ICMP → SYN scan → port scan → SQL injection → normalization → command injection → XSS → service scan → ICMP flood → DNS anomaly.

Bạn nên biến chính danh sách này thành 10 test scenarios.

Ví dụ:

tests/
├── 01_icmp/
│   └── icmp_normal.pcap
│
├── 02_syn_scan/
│   └── syn_scan.pcap
│
├── 03_port_scan/
│   └── port_scan.pcap
│
├── 04_sqli/
│   └── sql_injection.pcap
│
├── 05_sqli_evasion/
│   └── sql_comment_evasion.pcap
│
├── 06_command_injection/
│   └── command_injection.pcap
│
├── 07_xss/
│   └── xss.pcap
│
├── 08_service_scan/
│   └── service_scan.pcap
│
├── 09_icmp_flood/
│   └── icmp_flood.pcap
│
└── 10_dns/
    └── dns_anomaly.pcap
3. Nhưng có một điểm rất quan trọng: đừng capture “một mớ traffic”

Ví dụ bạn muốn test SYN Scan.

Không nên:

START CAPTURE

ping
HTTP
DNS
SSH
Nmap
Firefox
DNS
ping
Nmap
...

STOP

rồi gọi đó là:

syn_scan.pcap

Vì sau này bạn không biết packet nào thuộc test nào.

Thay vào đó:

START CAPTURE
       ↓
chỉ thực hiện scenario SYN scan
       ↓
STOP CAPTURE
       ↓
syn_scan_01.pcap

Sau đó test scenario tiếp theo.

4. Với trường hợp của bạn, topology nên là
             ┌────────────────┐
             │  Kali Attacker │
             │                │
             │  192.168.100.10│
             └───────┬────────┘
                     │
                     │ traffic
                     ↓
             ┌────────────────┐
             │   IDS Ubuntu   │
             │                │
             │  promiscuous   │
             │     NIC        │
             └───────┬────────┘
                     │
                     │
             ┌───────▼────────┐
             │ Ubuntu Victim  │
             │                │
             │ 192.168.100.30 │
             │                │
             │ SSH :22        │
             │ HTTP :80       │
             │ Juice :3000    │
             └────────────────┘

Và IDS không nhất thiết phải là bên thực hiện traffic.

Nó chỉ:

              observe
Kali ─────────────────────► Victim
          │
          │
          ▼
         IDS

Điều này rất đúng với bản chất IDS của bạn: input là network traffic và IDS quan sát traffic từ interface.

5. Một test case hoàn chỉnh sẽ như thế này

Ví dụ bạn đang test Port Scan.

Step 1 — Xóa PCAP cũ

Trên IDS:

rm -f port_scan.pcap
Step 2 — Chạy IDS capture

Ví dụ:

sudo python3 capture.py \
    -i enp0s3 \
    -o port_scan.pcap
Step 3 — Sang Kali

Thực hiện một hoạt động scan trong lab của bạn.

Ví dụ theo đúng rule trong project của bạn, detection sẽ dựa vào số lượng destination port và time window. File của bạn mô tả port scan là theo dõi unique_dst_ports trong một khoảng thời gian.

Step 4 — Dừng capture
Ctrl+C

Bạn có:

port_scan.pcap
Step 5 — Test Decoder
python3 phase2_decode.py port_scan.pcap

Bạn muốn thấy đại loại:

TCP
KALI:xxxxx
      ↓
VICTIM:22
SYN

TCP
KALI:xxxxx
      ↓
VICTIM:23
SYN

TCP
KALI:xxxxx
      ↓
VICTIM:25
SYN

...

Đây sẽ kiểm tra trực tiếp những field mà Packet object của bạn đang lưu: IP, protocol, TCP ports, sequence, ACK, flags, payload và flow key.

6. Sau đó test Flow Manager

Cùng PCAP đó:

port_scan.pcap
       ↓
Packet[]
       ↓
FlowManager
       ↓
5-tuple
       ↓
Flow table

Bạn kiểm tra:

src_ip
dst_ip
src_port
dst_port
protocol

Có đúng không.

Project của bạn xác định flow key là:

(src_ip,
 dst_ip,
 src_port,
 dst_port,
 protocol)

và dùng nó cho flow tracking, TCP state, port-scan detection và behavioral detection.

7. Sau đó mới test Detection

Ví dụ:

port_scan.pcap
       ↓
Decoder
       ↓
FlowManager
       ↓
PortTracker
       ↓
unique_dst_ports
       ↓
threshold
       ↓
ALERT

Ví dụ output:

{
  "rule_id": "10003",
  "attack_type": "PORT_SCAN",
  "source_ip": "192.168.100.10",
  "destination_ip": "192.168.100.30",
  "severity": "high"
}

Điều này phù hợp với Alert Engine mà bạn đã thiết kế: timestamp, rule ID, attack type, source/destination, evidence và severity.

8. Đối với Web Attack thì càng nên tự tạo PCAP

Đây mới là phần rất đáng giá cho project của bạn.

Ví dụ:

Kali
  │
  │ HTTP request
  ↓
DVWA
  │
  ↓
IDS

Bạn tạo traffic HTTP trong lab → IDS capture → PCAP.

Sau đó:

PCAP
 ↓
TCP packets
 ↓
TCP Stream
 ↓
Reassembly
 ↓
HTTP payload
 ↓
Normalization
 ↓
Signature Engine
 ↓
SQL_INJECTION

Đây chính xác là lý do bạn xây TCP reassembly và normalization. File của bạn mô tả rõ rằng payload có thể bị chia thành nhiều TCP packet và IDS cần reconstruct stream trước khi detection.

9. Đặc biệt hãy tạo 2 PCAP cho cùng một attack

Đây là phần tôi nghĩ sẽ làm project của bạn có chiều sâu hơn rất nhiều.

Ví dụ SQL injection:

PCAP A — straightforward
SQLi
   ↓
TCP packets
   ↓
reassembly
   ↓
normalization
   ↓
signature
   ↓
MATCH
PCAP B — obfuscated/encoded
SQLi
   ↓
encoding / comment / packet segmentation
   ↓
TCP packets
   ↓
reassembly
   ↓
normalization
   ↓
signature
   ↓
MATCH

Bạn có thể chứng minh:

IDS không chỉ detect payload “đẹp”, mà còn xử lý một số dạng obfuscation.

Đây phù hợp trực tiếp với mục tiêu anti-evasion trong project của bạn, bao gồm TCP reassembly, URL decoding, HTTP normalization và các dạng encoding/comment-based evasion.

10. Và đây là cách tôi sẽ xây dataset cho project của bạn

Tôi sẽ làm khoảng 20–30 PCAP nhỏ, thay vì một vài PCAP khổng lồ.

DATASET
│
├── BENIGN
│   ├── HTTP
│   ├── SSH
│   ├── DNS
│   └── ICMP
│
├── RECON
│   ├── SYN_SCAN_01
│   ├── SYN_SCAN_02
│   ├── PORT_SCAN_01
│   └── SERVICE_SCAN_01
│
├── WEB
│   ├── SQLI_01
│   ├── SQLI_02
│   ├── SQLI_EVASION_01
│   ├── XSS_01
│   └── COMMAND_INJECTION_01
│
└── ANOMALY
    ├── ICMP_FLOOD_01
    └── DNS_ANOMALY_01

Mỗi scenario nên có:

PCAP
+
scenario description
+
expected detection
+
expected rule ID

Ví dụ:

port_scan_01.pcap

Expected:
    Rule 10003
    PORT_SCAN
    severity = high
Và có một điều tôi muốn bạn làm khác với cách bạn đang nghĩ

Đừng coi Kali là “máy tạo dữ liệu attack”.

Hãy coi nó là traffic generator.

Kali
 │
 ├── benign traffic
 │
 └── suspicious traffic
          │
          ▼
       Network
          │
          ▼
         IDS
          │
          ▼
       PCAP

Sau này khi project trưởng thành, bạn có thể bổ sung:

                DATA SOURCES
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
   Your Lab      Public PCAP    Synthetic
       │             │             │
       └─────────────┼─────────────┘
                     ▼
                 Test Suite
                     │
                     ▼
                    IDS

Lab tự tạo dùng để debug và regression test.
PCAP public dùng để kiểm tra khả năng hoạt động trên traffic mà bạn không tự tạo.
Synthetic traffic có thể dùng sau này để tạo các edge case rất cụ thể cho TCP reassembly, fragmentation hoặc normalization.

Với project hiện tại của bạn, tôi sẽ làm ngay theo thứ tự này:
1. BENIGN ping
       ↓
2. BENIGN HTTP
       ↓
3. BENIGN SSH
       ↓
4. SYN scan
       ↓
5. Port scan
       ↓
6. HTTP SQLi
       ↓
7. SQLi encoded/comment
       ↓
8. XSS
       ↓
9. Command injection

Chưa cần làm ICMP flood, DNS tunneling hay các test phức tạp ngay. Hãy dùng 1→9 để chứng minh Capture → Decode → Flow → Reassembly → Normalization → Detection hoạt động end-to-end trước. Cách này cũng đúng với roadmap trong file của bạn, vốn yêu cầu kiểm thử ping + nmap ngay sau Packet Object và 5-tuple.

Nếu bạn muốn đi theo trường hợp 2, bước tiếp theo hợp lý nhất là 
tôi có thể thiết kế cho bạn một “test plan” cụ thể Kali → Victim → IDS, trong đó với từng scenario 
tôi chỉ rõ Kali chạy gì → IDS bắt lúc nào → PCAP phải chứa những packet/field nào → Decoder/Flow/Detection phải cho output gì.