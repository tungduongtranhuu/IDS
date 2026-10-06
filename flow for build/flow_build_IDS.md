## Điểm quan trọng nhất


> **Capture → Decode → Flow → Reassembly → Normalization → Detection → Alert → SIEM**

Sau đó mới benchmark và tối ưu.

### Input của IDS là Network Traffic

**Điểm cực kỳ quan trọng:** Input của IDS **không phải là "attack"**. Input là **network traffic** (bình thường + độc hại). IDS quan sát traffic từ interface mạng, sau đó quyết định traffic nào đáng báo động.

Ví dụ:
- Traffic bình thường: HTTP GET request, DNS query, ping
- Traffic độc hại: SQL injection payload, port scan, ICMP flood

IDS phải có khả năng phân biệt cả hai.

## 1. Kiến trúc mình đề xuất cho project của bạn

Flow mới nên là:

```text
                    ┌───────────────────────┐
                    │     KALI ATTACKER     │
                    │  Nmap / SQLMap / ...  │
                    └───────────┬───────────┘
                                │
                                │ traffic
                                ▼
                    ┌───────────────────────┐
                    │    Ubuntu IDS VM      │
                    │                       │
                    │  Promiscuous NIC      │
                    └───────────┬───────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                    PROCESS 1                                │
│                 PACKET CAPTURE                              │
│                                                             │
│ Raw Socket / libpcap                                        │
│        ↓                                                    │
│ Ethernet decoder                                            │
│        ↓                                                    │
│ IP decoder                                                  │
│        ↓                                                    │
│ TCP/UDP/ICMP decoder                                        │
│        ↓                                                    │
│ Packet metadata                                             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    PROCESS 2                                │
│              FLOW + REASSEMBLY                              │
│                                                             │
│ 5-tuple                                                     │
│        ↓                                                    │
│ Flow Table                                                  │
│        ↓                                                    │
│ IP Fragment Reassembly                                      │
│        ↓                                                    │
│ TCP Stream Reassembly                                       │
│        ↓                                                    │
│ Application payload                                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    PROCESS 3                                │
│             NORMALIZATION ENGINE                            │
│                                                             │
│ URL decode                                                  │
│ HTML/HTTP normalization                                     │
│ lowercase                                                   │
│ whitespace normalization                                    │
│                                                             │
│ Raw Payload ──────────► Normalized Payload                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    PROCESS 4                                │
│                 DETECTION ENGINE                            │
│                                                             │
│                 ┌──────────────────┐                        │
│                 │ Rule Manager     │                        │
│                 └────────┬─────────┘                        │
│                          │                                  │
│             ┌────────────┴─────────────┐                    │
│             ▼                          ▼                    │
│       Signature Rules            Behavioral Rules           │
│       Aho-Corasick               State Tracking             │
│             │                          │                    │
│             └────────────┬─────────────┘                    │
│                          ▼                                  │
│                     Detection                              │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    PROCESS 5                                │
│                  ALERT ENGINE                               │
│                                                             │
│ Rule ID                                                     │
│ Attack Type                                                 │
│ Source / Destination                                        │
│ Timestamp                                                   │
│ Evidence                                                    │
│ Severity                                                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
                  ECS JSON / alerts.json
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
            Wazuh                       ELK
```

---

# 2. Sau khi xong Step 1, bạn nên làm gì?

Bạn đã xong:

```text
STEP 1
VirtualBox
   ↓
Kali
Ubuntu IDS
Metasploitable2
   ↓
Internal Network
   ↓
Connectivity
```

Bước tiếp theo phải là:

# PHASE 2 — Packet Capture + Decoder

Mục tiêu đầu tiên cực kỳ đơn giản:

> **Nhìn thấy packet thực sự đi qua Ubuntu IDS.**

**Workflow Phase 2:**

```text
Raw Network Traffic
        ↓
   [STEP 2.0] PCAP file format (xem packet_capture.py)
        ↓
   [STEP 2.1] Raw socket capture
        ↓
   [STEP 2.2] PCAP Writing
        ↓
   [STEP 2.3-2.7] Decode từng layer (Ethernet, IP, TCP/UDP/ICMP)
        ↓
   [STEP 2.8] Build Packet objects (xem packet_decode.py)
        ↓
   [STEP 2.9] Statistics output
        ↓
   Decoder.packets[] → 1000+ Packet objects
        ↓
   Phase 3: Flow Manager
```

---

# STEP 2.0 — PCAP File Format (Khái niệm)

Trước khi viết code, cần hiểu PCAP file structure được dùng bởi **PcapWriter class** (xem [packet_capture.py](../../ids/phase%202/packet_capture.py)).

PCap là file format chuẩn để lưu trữ captured packets. Được hỗ trợ bởi Wireshark, tcpdump, và dpkt.

**PCAP file gồm 3 phần:**

1. **Global Header** (24 bytes - viết một lần duy nhất)
   - magic_number: `0xA1B2C3D4` - định danh file PCAP
   - version_major: `2`
   - version_minor: `4`
   - thiszone: `0` - không sử dụng timezone
   - sigfigs: `0` - độ chính xác timestamp
   - snaplen: `65535` - max bytes per packet
   - network: `1` - Ethernet

2. **Packet Record Header** (16 bytes - lặp lại cho mỗi packet)
   - ts_sec: giây (Unix timestamp)
   - ts_usec: microsecond
   - incl_len: captured length (actual bytes)
   - orig_len: original length (wire length)

3. **Packet Data** (raw bytes - lặp lại cho mỗi packet)
   - Raw Ethernet frame data

Ví dụ struct format từ **PcapWriter class** (packet_capture.py line 74-85):
```python
class PcapWriter:
    def __init__(self, filename):
        # Global header
        global_header = struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,    # magic number
            2,              # version major
            4,              # version minor
            0,              # thiszone
            0,              # sigfigs
            65535,          # snaplen
            1               # network (Ethernet)
        )
        self.file.write(global_header)
    
    def write_packet(self, packet_data):
        # Packet header + data
        timestamp = time.time()
        seconds = int(timestamp)
        microseconds = int((timestamp - seconds) * 1_000_000)
        
        packet_header = struct.pack(
            "<IIII",
            seconds,
            microseconds,
            len(packet_data),    # captured length
            len(packet_data)     # wire length
        )
        self.file.write(packet_header)
        self.file.write(packet_data)
```

**Tại sao PCAP?**
- Chuẩn quốc tế, hỗ trợ rộng rãi
- Dễ import vào Wireshark, tcpdump để debug
- dpkt có thể parse trực tiếp
- Thuận tiện cho testing và replay attacks

---

# STEP 2.1 — Capture packet

Trên Ubuntu:

```bash
ip link
```

xác định interface:

```text
enp0s3
```

Sau đó viết:

```python
import socket

sock = socket.socket(
    socket.AF_PACKET,
    socket.SOCK_RAW,
    socket.ntohs(3)
)

while True:
    raw_packet, addr = sock.recvfrom(65535)

    print(len(raw_packet))
```

Sau đó từ Kali:

```bash
ping 192.168.100.30
```

Ubuntu phải thấy packet.

---

# STEP 2.2 — Decode Ethernet

Dùng:

```bash
pip install dpkt
```

Sau đó:

```python
import dpkt

eth = dpkt.ethernet.Ethernet(raw_packet)

print(eth.src)
print(eth.dst)
print(eth.type)
```

Bạn cần hiểu:

```text
Raw bytes
   ↓
Ethernet
   ↓
Ethernet header
   ↓
IP packet
```
--- 
Structure
Packet
├── timestamp
├── Ethernet
│   ├── src_mac
│   ├── dst_mac
│   └── ethertype
├── IPv4
│   ├── src_ip
│   ├── dst_ip
│   ├── protocol
│   ├── ttl
│   ├── id
│   ├── length
│   └── fragmentation
├── TCP
│   ├── src_port
│   ├── dst_port
│   ├── seq
│   ├── ack
│   ├── flags
│   └── window
├── UDP
│   ├── src_port
│   └── dst_port
├── ICMP
│   ├── type
│   └── code
├── payload
└── flow_key
---

# STEP 2.3 — Decode IPv4

```python
ip = eth.data

print(ip.src)
print(ip.dst)
print(ip.p)
```

Convert IP:

```python
import socket

src_ip = socket.inet_ntoa(ip.src)
dst_ip = socket.inet_ntoa(ip.dst)
```

Output:

```text
192.168.100.10
192.168.100.30
```

---

# STEP 2.4 — Decode TCP

Nếu:

```python
isinstance(ip.data, dpkt.tcp.TCP)
```

thì:

```python
tcp = ip.data

print(tcp.sport)
print(tcp.dport)
print(tcp.seq)
print(tcp.ack)
print(tcp.flags)
print(tcp.data)
```

Bây giờ bạn có:

```text
SRC IP
DST IP
SRC PORT
DST PORT
PROTOCOL
SEQ
ACK
FLAGS
PAYLOAD
```

Đây chính là dữ liệu nền tảng cho toàn bộ IDS.

---

# 3. Tạo Packet Object (Abstraction Layer)

Đừng để code detection xử lý trực tiếp `dpkt`. Cần tạo một lớp trừu tượng để:
- Tách biệt detection engine khỏi dpkt library
- Dễ dàng pass data giữa các phase
- Dễ test và debug
- Dễ mở rộng thêm fields sau

Xem [packet_decode.py](../../ids/phase%202/packet_decode.py) (line 57-150) - **@dataclass Packet**:

```python
@dataclass
class Packet:
    # Capture metadata
    timestamp: float
    capture_length: Optional[int] = None
    wire_length: Optional[int] = None

    # Ethernet
    src_mac: str = "unknown"
    dst_mac: str = "unknown"
    ethertype: Optional[int] = None

    # IPv4
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_protocol: Optional[str] = None  # "TCP", "UDP", "ICMP"
    ip_protocol_number: Optional[int] = None  # 6, 17, 1
    ip_ttl: Optional[int] = None
    ip_id: Optional[int] = None

    # TCP
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_flags: Optional[int] = None  # bitmask
    tcp_flags_text: Optional[str] = None  # "SYN,ACK"
    tcp_window: Optional[int] = None

    # UDP
    udp_length: Optional[int] = None

    # ICMP
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # Transport ports
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # Payload
    payload: bytes = field(default_factory=bytes)

    # Flow
    flow_key: Optional[tuple] = None  # (src_ip, dst_ip, src_port, dst_port, protocol)
    ip_fragment_key: Optional[tuple] = None  # (src_ip, dst_ip, protocol, ip_id)
```

**Lợi ích:**
- Giảm coupling giữa decoder và detection engine
- Dễ serialize/deserialize
- Dễ logging và debugging
- Contract rõ ràng giữa Phase 2 (Decode) và Phase 3+ (Flow/Detection)

---

# 4. STEP 2.5 — Tạo Flow Key (5-Tuple)

Flow key là tuple **unidirectional** để nhận dạng một stream duy nhất.

Xem [packet_decode.py](../../ids/phase%202/packet_decode.py) (line 378-385 - TCP) và (line 422-430 - UDP):

```python
# 5-tuple (DIRECTIONAL)
flow_key = (
    src_ip,          # "192.168.100.10"
    dst_ip,          # "192.168.100.30"
    src_port,        # 54321
    dst_port,        # 80
    protocol         # "TCP"
)
```

Ví dụ thực tế:
```python
flow_key = ("192.168.100.10", "192.168.100.30", 54321, 80, "TCP")
```

**Lưu ý:** Flow key là **unidirectional** (có hướng):
- `(192.168.100.10, 192.168.100.30, 54321, 80, TCP)` ≠ `(192.168.100.30, 192.168.100.10, 80, 54321, TCP)`

Tuy nhiên, để track một **connection** đầy đủ, Phase 3 nên:
1. Giữ cả 2 direction riêng biệt
2. Hoặc canonicalize thành bidirectional key:
   ```python
   canonical_key = tuple(sorted([
       (src_ip, dst_ip, src_port, dst_port),
       (dst_ip, src_ip, dst_port, src_port)
   ]))
   ```

**Flow key được dùng để:**
- TCP stream reassembly (tìm tất cả packets của cùng connection)
- State tracking (SYN → ESTABLISHED → FIN)
- Port scan detection (unique_dst_ports per src_ip)
- Flow statistics (bytes, packets, duration)
- Behavioral detection

---

# 5. STEP 3 — Flow Manager

Tạo:

```text
FlowManager
```

Ví dụ:

```python
flows = {}

flows[flow_key] = TCPFlow(...)
```

Mỗi flow lưu:

```text
TCPFlow
│
├── src
├── dst
├── state
├── packets
├── seq tracking
├── payload buffer
├── first_seen
└── last_seen
```

TCP state:

```text
SYN
 ↓
SYN-ACK
 ↓
ACK
 ↓
ESTABLISHED
 ↓
FIN
 ↓
CLOSED
```

---

# 6. STEP 4 — TCP Reassembly

Đây mới là anti-evasion đầu tiên.

Ví dụ attacker gửi:

```text
Packet 1
SEQ=1000
payload="UNION "

Packet 2
SEQ=1006
payload="SELECT "

Packet 3
SEQ=1013
payload="password"
```

Nếu detection từng packet:

```text
Packet 1
"UNION "
      ❌

Packet 2
"SELECT "
      ❌

Packet 3
"password"
      ❌
```

IDS không phát hiện được.

Nhưng reassembly:

```text
UNION SELECT password
```

→ detection thành công.

Đây chính là lý do Snort phải có stream processing/reassembly.

---

# 7. Bạn nên làm TCP Reassembly theo 3 milestone

### Version 1

Chỉ xử lý packet đúng thứ tự:

```text
1000
1006
1013
```

---

### Version 2

Xử lý out-of-order:

```text
1000
1013
1006
```

Buffer:

```text
1000 → "UNION "
1006 → "SELECT "
1013 → "password"
```

→ assemble.

---

### Version 3

Xử lý overlap:

```text
SEQ 1000
SEQ 1005
```

và duplicate.

Đây mới bắt đầu trở thành **anti-evasion engine thực sự**.

---

# 8. STEP 5 — IP Fragment Reassembly

Sau TCP reassembly mới làm IP fragmentation.

Ví dụ:

```text
Original packet

      ┌─────────────────────────┐
      │ "UNION SELECT password" │
      └─────────────────────────┘

             ↓ fragment

Fragment 1
"UNION "

Fragment 2
"SELECT "

Fragment 3
"password"
```

Nếu IDS chỉ inspect từng fragment:

```text
UNION
SELECT
password
```

→ có thể bypass signature.

Engine của bạn phải:

```text
IP fragments
     ↓
identify:
src + dst + protocol + ID
     ↓
sort by offset
     ↓
reassemble
     ↓
TCP
```

---

# 9. STEP 6 — Normalization

Sau khi reassembly:

```text
Raw payload
      ↓
Normalization
      ↓
Detection
```

Nhưng mình muốn sửa roadmap cũ của bạn ở một điểm.

**Không nên chỉ lowercase + URL decode một lần.**

Ví dụ:

```text
%55%4E%49%4F%4E
```

→

```text
UNION
```

hoặc:

```text
%2527
```

có thể yêu cầu nhiều tầng decoding tùy context.

Bạn nên tạo:

```text
Normalizer
│
├── URL decode
├── lowercase
├── whitespace normalization
├── HTTP-specific normalization
└── optional repeated decoding
```

Nhưng:

> **Giữ RAW payload và NORMALIZED payload riêng biệt.**

Đừng overwrite raw data.

```text
raw_payload
      │
      ├──────────────► evidence/log
      │
      ▼
normalizer
      │
      ▼
normalized_payload
      │
      ▼
detection
```

---

# 10. Bây giờ mới tới Rule Engine

Tạo:

```text
rules/
├── web.yaml
├── scan.yaml
├── network.yaml
└── local.yaml
```

Ví dụ:

```yaml
rules:
  - sid: 10001
    msg: "SQL Injection Attempt"
    protocol: tcp
    dst_port: 80
    pattern: "union select"
    severity: high
```

---

# 11. Nhưng mình muốn nâng Rule Schema của bạn

Schema cũ:

```yaml
pattern
protocol
dst_port
```

hơi đơn giản.

Nên thiết kế:

```yaml
- sid: 10001
  name: SQL_INJECTION_UNION_SELECT
  description: SQL UNION SELECT injection attempt

  protocol: tcp

  flow:
    direction: to_server

  destination:
    ports: [80, 443]

  detection:
    type: content
    pattern: "union select"
    nocase: true

  severity: high

  tags:
    - web
    - sql-injection
```

Sau này bạn có thể thêm:

```yaml
detection:
  type: regex
```

hoặc:

```yaml
detection:
  type: threshold
```

hoặc:

```yaml
detection:
  type: behavioral
```

Đây sẽ trở thành **mini rule language** của chính IDS bạn.

---

# 12. RULE 1 — ICMP Detection

Đây là rule đầu tiên mình khuyên bạn viết.

```yaml
- sid: 10001
  name: ICMP_TRAFFIC
  description: ICMP packet detected

  protocol: icmp

  detection:
    type: protocol

  severity: low
```

Test:

```bash
ping 192.168.100.30
```

IDS:

```text
ICMP packet
    ↓
Rule 10001
    ↓
MATCH
    ↓
ALERT
```

Mục tiêu:

> Kiểm tra toàn bộ pipeline hoạt động.

---

# 13. RULE 2 — SYN Scan

Tiếp theo:

```text
Kali
 ↓
nmap
 ↓
Ubuntu IDS
```

Rule:

```yaml
- sid: 10002
  name: TCP_SYN_SCAN
  description: Possible TCP SYN port scan

  protocol: tcp

  detection:
    type: threshold
    flags: SYN
    unique_destination_ports: 20
    window: 5

  severity: medium
```

Logic:

```text
source IP
    │
    ├── SYN → port 21
    ├── SYN → port 22
    ├── SYN → port 23
    ├── SYN → port 25
    ├── SYN → port 53
    ├── ...
    └── >20 ports / 5 sec
                │
                ▼
             ALERT
```

Test:

```bash
nmap -sS 192.168.100.30
```

---

# 14. RULE 3 — Port Scan

Tách riêng khỏi SYN scan.

Rule:

```yaml
- sid: 10003
  name: PORT_SCAN
  description: Multiple destination ports accessed by one source

  detection:
    type: behavioral

    threshold:
      unique_dst_ports: 30
      time_window: 5

  severity: high
```

State:

```text
Source IP
   │
   ▼
PortTracker
   │
   ├── 21
   ├── 22
   ├── 23
   ├── 25
   ├── 53
   ├── 80
   ├── 110
   └── ...
```

Nếu:

```text
unique ports >= 30
AND
time <= 5 sec
```

→ alert.

---

# 15. RULE 4 — HTTP SQL Injection

Đây là rule signature đầu tiên thực sự đáng làm.

```yaml
- sid: 10004
  name: SQL_INJECTION_UNION_SELECT
  description: Possible SQL UNION SELECT injection

  protocol: tcp

  destination:
    ports: [80, 8080, 443]

  detection:
    type: content
    buffer: http_uri
    pattern: "union select"
    nocase: true

  severity: high
```

Test:

```bash
sqlmap -u "http://192.168.100.30/..."
```

hoặc tự gửi:

```http
GET /index.php?id=1 UNION SELECT username,password FROM users
```

Flow:

```text
HTTP
 ↓
URI
 ↓
Normalization
 ↓
"union select"
 ↓
Aho-Corasick
 ↓
SID 10004
 ↓
ALERT
```

---

# 16. RULE 5 — SQL Comment Evasion

Đây là rule rất quan trọng để chứng minh **anti-evasion**.

Attacker:

```text
UNION/**/SELECT
```

Rule đơn giản:

```text
"union select"
```

→ ❌

Bạn cần normalization:

```text
UNION/**/SELECT
       ↓
remove/normalize comments
       ↓
UNION SELECT
       ↓
MATCH
```

Rule:

```yaml
- sid: 10005
  name: SQL_COMMENT_EVASION
  description: SQL injection using inline comments

  detection:
    type: regex
    pattern: "(?i)union\\s*/\\*.*?\\*/\\s*select"

  severity: high
```

Sau này bạn có thể test:

```bash
sqlmap --tamper=space2comment
```

**Đây mới là một demo rất đẹp cho CV:**

> Implemented TCP stream reassembly and payload normalization to detect signature-based attacks despite packet fragmentation and common encoding/comment-based evasion techniques.

---

# 17. RULE 6 — HTTP Command Injection

Ví dụ:

```text
GET /ping?host=127.0.0.1;cat+/etc/passwd
```

Rule:

```yaml
- sid: 10006
  name: COMMAND_INJECTION
  detection:
    type: content
    buffer: http_uri
    patterns:
      - ";cat "
      - "|cat "
      - "&&cat "
      - "/etc/passwd"

  severity: critical
```

Aho-Corasick rất phù hợp cho nhóm signature này.

---

# 18. RULE 7 — XSS

Ví dụ:

```html
<script>alert(1)</script>
```

Rule:

```yaml
- sid: 10007
  name: XSS_SCRIPT_TAG
  detection:
    type: content
    buffer: http_uri
    pattern: "<script"
    nocase: true

  severity: high
```

Sau normalization:

```text
%3Cscript%3E
       ↓
<script>
       ↓
MATCH
```

---

# 19. RULE 8 — Nmap Service Scan

Có thể xây behavioral detection:

```yaml
- sid: 10008
  name: SERVICE_SCAN
  detection:
    type: behavioral

    threshold:
      unique_destination_ports: 10
      time_window: 3

  severity: medium
```

Nhưng nên phân biệt:

```text
PORT_SCAN
SERVICE_SCAN
SYN_SCAN
```

không nhất thiết là ba detection hoàn toàn giống nhau.

Đây là cơ hội để bạn thiết kế **attack taxonomy**.

---

# 20. RULE 9 — ICMP Flood

Ví dụ:

```yaml
- sid: 10009
  name: ICMP_FLOOD
  protocol: icmp

  detection:
    type: threshold
    packets: 100
    window: 1

  severity: high
```

Logic:

```text
Source IP
    │
    ├── ICMP
    ├── ICMP
    ├── ICMP
    ├── ...
    └── 100 packets / second
             ↓
           ALERT
```

**Mục đích:** Phát hiện ĐDoS attacks sử dụng ICMP (ping flood, smurf).

---

# 21. RULE 10 — DNS Tunneling

Đây là rule nâng cao.

Không dùng Aho-Corasick.

Bạn extract:

```text
DNS query
```

Feature:

```text
query_length
subdomain_length
entropy
query_frequency
unique_domains
```

Ví dụ:

```text
aj3k29x8d9a8s7d6.example.com
```

Nếu:

```text
length > threshold
AND
entropy high
AND
frequency high
```

→:

```text
POSSIBLE_DNS_TUNNEL
```

Rule schema:

```yaml
- sid: 10010
  name: POSSIBLE_DNS_TUNNEL
  protocol: udp
  dst_port: 53

  detection:
    type: behavioral

    features:
      query_length: 50
      entropy: 4.0
      queries_per_second: 20

  severity: high
```

Đây là nơi IDS của bạn bắt đầu vượt khỏi kiểu:

> "signature scanner"

và trở thành:

> **hybrid IDS.**

---

# 22. Ba loại Detection Engine (align với nội dung project.md)

Như phân tích trong **nội dung project.md section 17**, IDS có 3 loại detection. **Đừng bắt mọi thứ vào Aho-Corasick.**

## 1. Signature Detection (Aho-Corasick)

**Mục đích:** Tìm kiếm những known attack patterns cố định trong payload.

**Phù hợp với:**
```text
"union select"          # SQL injection
"/etc/passwd"           # File disclosure
"<script"              # XSS script tag
"<?php"                # PHP code injection
"cmd.exe"              # Windows command
"powershell"           # PowerShell
"wget "                # Tool usage
"curl "                # Tool usage
"exec("                # Code execution
"eval("                # Code execution
```

**Implementation:** Sử dụng Aho-Corasick automaton để match multiple patterns song song.

---

## 2. Pattern/Regex Detection

**Mục đích:** Phát hiện complex attack patterns với variable structure.

**Phù hợp với:**
```text
UNION\s*/\*.*?\*/\s*SELECT     # SQL comment evasion
<\s*iframe.*?>                 # XSS iframe
javascript\s*:\s*             # XSS javascript: protocol
\.(exe|dll|sys)\s*$            # Binary file extension
ROOTKIT|TROJAN|BACKDOOR        # Malware signatures
```

**Implementation:** Compile regex patterns và test từng payload.

---

## 3. Behavioral Detection (Stateful + Threshold)

**Mục đích:** Phát hiện attack patterns không dựa trên payload mà trên hành vi network.

**Phù hợp với:**
```text
Port scan:              unique_dst_ports >= 30 in 5 seconds
SYN scan:               SYN flags >= 20 from same src_ip in 5 sec
SYN flood:              SYN packets >= 100 from same src in 1 sec
ICMP flood:             ICMP packets >= 100 to same dst in 1 sec
Brute force (DNS):      DNS queries >= 20 per second
DNS tunneling:          query_length > 50 + entropy > 4.0 + freq > 20/sec
```

**Implementation:** 
- Maintain flow state (5-tuple → TCPFlow object)
- Track statistics per flow (packet count, unique ports, etc.)
- Apply thresholds + time windows
- Generate alert khi exceed threshold

Kiến trúc:

```text
                 Detection Engine
                       │
       ┌───────────────┼────────────────┐
       │               │                │
       ▼               ▼                ▼
 Aho-Corasick       Regex          Behavioral
       │               │                │
       ▼               ▼                ▼
 Signatures        Complex        Threshold/
                  patterns         State
       │               │                │
       └───────────────┼────────────────┘
                       ▼
                    Alert
```

Đây là kiến trúc mình khuyên bạn giữ.

---

# 23. Process Architecture (Single Process MVP)

Sau khi hoàn thiện MVP, architecture sẽ như sau.

**V1 - Single Process (correctness first, không multiprocessing):**

```text
                RAW NETWORK TRAFFIC
                       │
                       ▼
        ┌──────────────────────────────┐
        │      PHASE 2: CAPTURE        │
        │                              │
        │ Raw Socket (AF_PACKET)       │
        │ ↓                            │
        │ Read Ethernet frames         │
        │ ↓                            │
        │ Write to PCAP file           │
        └──────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │   PHASE 2: DECODE (dpkt)     │
        │                              │
        │ Decode Ethernet              │
        │ ↓                            │
        │ Decode IPv4 / IPv6           │
        │ ↓                            │
        │ Decode TCP/UDP/ICMP          │
        │ ↓                            │
        │ Create Packet objects        │
        └──────────────────────────────┘
                       │
                   Packet[]
                       ▼
        ┌──────────────────────────────┐
        │   PHASE 3: FLOW MANAGER      │
        │                              │
        │ Extract flow_key (5-tuple)   │
        │ ↓                            │
        │ Create/update TCPFlow()      │
        │ ↓                            │
        │ Track TCP state              │
        └──────────────────────────────┘
                       │
                   FlowDict
                       ▼
        ┌──────────────────────────────┐
        │  PHASE 4: REASSEMBLY         │
        │                              │
        │ IP Fragment Reassembly       │
        │ ↓                            │
        │ TCP Stream Reassembly        │
        │ ↓                            │
        │ Reconstruct full payloads    │
        └──────────────────────────────┘
                       │
              ReassembledStream
                       ▼
        ┌──────────────────────────────┐
        │   PHASE 5: NORMALIZATION     │
        │                              │
        │ raw_payload                  │
        │ ↓                            │
        │ URL decode                   │
        │ ↓                            │
        │ Lowercase                    │
        │ ↓                            │
        │ Whitespace normalization     │
        │ ↓                            │
        │ normalized_payload           │
        │                              │
        │ (keep both raw + normalized) │
        └──────────────────────────────┘
                       │
        normalized_stream + evidence
                       ▼
        ┌──────────────────────────────┐
        │  PHASE 6: DETECTION ENGINE   │
        │                              │
        │        Signature             │
        │     Aho-Corasick             │
        │        ├─ Rule 10001-10007   │
        │        │                     │
        │        Regex                 │
        │     Pattern match            │
        │        ├─ Rule 10005 (...)   │
        │        │                     │
        │        Behavioral            │
        │     State + Threshold        │
        │        ├─ Rule 10002 (SYN)   │
        │        ├─ Rule 10003 (Port)  │
        │        └─ Rule 10009-10010   │
        └──────────────────────────────┘
                       │
                    Match!
                       ▼
        ┌──────────────────────────────┐
        │   PHASE 7: ALERT ENGINE      │
        │                              │
        │ Create Alert object:         │
        │  - timestamp                 │
        │  - rule_id                   │
        │  - attack_type               │
        │  - severity                  │
        │  - source IP:port            │
        │  - dest IP:port              │
        │  - protocol                  │
        │  - evidence (raw payload)    │
        │  - detection_method          │
        │  - normalized_payload        │
        │                              │
        │ Write to alerts.json (ECS)   │
        └──────────────────────────────┘
                       │
                    ALERT
                       │
              ┌────────┴────────┐
              ▼                 ▼
            Wazuh              ELK
```

**Lưu ý:** 
- V1 là **single process**, chạy tuần tự
- Đảm bảo **correctness** trước khi tối ưu
- Sau khi V1 hoạt động, mới tách thành multiprocess (V2, V3, V4)

---

# 24. Nhưng đừng multiprocessing ngay

Mình muốn sửa một điểm quan trọng trong roadmap ban đầu.

**Đừng làm:**

```text
Process 1
Process 2
Process 3
```

ngay từ đầu.

Hãy làm:

### V1

```text
Single process
    ↓
Capture
    ↓
Decode
    ↓
Flow
    ↓
Reassembly
    ↓
Detection
    ↓
Alert
```

Đảm bảo correctness trước.

---

### V2

Tách:

```text
Capture
   ↓
Queue
   ↓
Detection
```

---

### V3

Tách:

```text
Capture
   ↓
Queue
   ↓
Reassembly
   ↓
Queue
   ↓
Detection
```

---

### V4

Benchmark:

```text
packet/sec
MB/sec
CPU
RAM
packet drops
detection latency
```

Rồi mới tối ưu.

Đây là cách làm chuyên nghiệp hơn việc ngay lập tức tuyên bố "high-performance".

---

# 25. Roadmap hoàn chỉnh của project

Mình sẽ viết lại thành:

```text
PHASE 1
LAB
✓ VirtualBox
✓ Kali
✓ Ubuntu
✓ Metasploitable
✓ Internal Network
✓ Promiscuous Mode
✓ Connectivity

        ↓

PHASE 2
PACKET CAPTURE
□ Raw Socket
□ Interface selection
□ Packet capture
□ Ethernet decoder
□ IPv4 decoder
□ TCP decoder
□ UDP decoder
□ ICMP decoder
□ Packet abstraction

        ↓

PHASE 3
FLOW ENGINE
□ 5-tuple
□ Flow table
□ TCP states
□ Connection timeout
□ Bidirectional flow

        ↓

PHASE 4
ANTI-EVASION
□ IP fragmentation
□ TCP reassembly
□ Out-of-order
□ Duplicate packets
□ Overlap handling
□ URL decoding
□ Lowercase
□ HTTP normalization

        ↓

PHASE 5
RULE ENGINE
□ YAML parser
□ Rule schema
□ Rule validation
□ SID management
□ Rule matching

        ↓

PHASE 6
SIGNATURE ENGINE
□ Aho-Corasick
□ Content rules
□ Case insensitive
□ Multiple patterns
□ Rule metadata

        ↓

PHASE 7
BEHAVIOR ENGINE
□ Threshold
□ Time window
□ Port scan
□ SYN scan
□ ICMP flood
□ Brute force
□ DNS anomaly

        ↓

PHASE 8
ALERT ENGINE
□ Alert object
□ Severity
□ Evidence
□ Timestamp
□ Source
□ Destination
□ SID
□ Attack category

        ↓

PHASE 9
SIEM
□ JSON
□ ECS mapping
□ File output
□ Wazuh
□ Elasticsearch
□ Kibana

        ↓

PHASE 10
EVASION LAB
□ Nmap
□ Nmap fragmentation
□ SQLMap
□ SQLMap tamper
□ URL encoding
□ HTTP fragmentation
□ TCP out-of-order
□ Duplicate segments

        ↓

PHASE 11
PERFORMANCE
□ multiprocessing
□ Queue
□ Shared memory
□ benchmark
□ packet drops
□ throughput
□ latency

        ↓

PHASE 12
ML OPTIONAL
□ Feature extraction
□ Isolation Forest
□ anomaly score
□ hybrid detection
```

---

# 26. Phạm vi cụ thể của IDS (align với nội dung project.md section 8-9)

IDS của bạn **không phải** nhằm phát hiện mọi attack. Phạm vi rõ ràng là:

```text
                   MINI NETWORK IDS
                          │
         ┌────────────────┼────────────────┐
         │                │                │
         ▼                ▼                ▼
   RECONNAISSANCE     WEB EXPLOIT      NETWORK ANOMALY
         │                │                │
         ├─ TCP SYN Scan  ├─ SQL Injection ├─ ICMP Flood
         ├─ Port Scan     ├─ XSS           └─ DNS Tunnel
         └─ Service Scan  └─ Cmd Injection
```

---

# 27. 10 Rules Implementation Order

**Đừng làm 10 rules cùng lúc.** Thứ tự dưới đây đảm bảo pipeline được test dần dần.

| Thứ tự | SID   | Rule Name                | Nhóm              | Mục tiêu                     |
|--------|-------|-------------------------|-------------------|-------------------------------|
| 1      | 10001 | ICMP_TRAFFIC            | Network Anomaly   | Test pipeline (protocol detect) |
| 2      | 10002 | TCP_SYN_SCAN            | Reconnaissance    | Test TCP flags + behavioral  |
| 3      | 10003 | PORT_SCAN               | Reconnaissance    | Test state tracking + threshold |
| 4      | 10004 | SQL_INJECTION_UNION     | Web Exploit       | Test signature detection     |
| 5      | 10005 | SQL_COMMENT_EVASION     | Web Exploit       | Test normalization + regex   |
| 6      | 10006 | COMMAND_INJECTION       | Web Exploit       | Test multi-pattern Aho-Corasick |
| 7      | 10007 | XSS_SCRIPT_TAG          | Web Exploit       | Test URL encoding normalization |
| 8      | 10008 | SERVICE_SCAN            | Reconnaissance    | Test behavioral refinement   |
| 9      | 10009 | ICMP_FLOOD              | Network Anomaly   | Test threshold + rate limiting |
| 10     | 10010 | POSSIBLE_DNS_TUNNEL     | Network Anomaly   | Test advanced behavioral     |

**Lý do thứ tự này:**
1. ICMP (đơn giản) → test toàn bộ pipeline
2. SYN Scan (TCP flags) → test TCP field handling
3. Port Scan (threshold) → test behavioral engine
4. HTTP SQLi (signature) → test Aho-Corasick
5-7. Web attacks (normalization + pattern) → test anti-evasion
8. Service Scan → refine behavioral logic
9-10. Advanced behavioral → DNS handling

---

# 27. Và đây mới là điểm mình muốn bạn hướng tới

Sau khi làm xong project, bạn **không nên mô tả trên CV** kiểu:

> "Created an IDS using Python and Aho-Corasick."

Quá bình thường.

Bạn có thể mô tả:

> **Designed and implemented a modular network IDS in Python with packet capture, TCP flow tracking, IP/TCP reassembly, payload normalization, signature-based detection using Aho-Corasick, behavioral detection with stateful thresholds, and ECS-compatible security event logging.**

Và phần anti-evasion:

> **Implemented packet/stream reassembly and payload normalization to detect attacks fragmented across packets and obfuscated through URL encoding, case manipulation and HTTP comment-based evasion.**

Đây mới thực sự thể hiện tư duy **Security Engineer / Detection Engineer**.

---

## Việc bạn nên làm ngay bây giờ

Bạn đã hoàn thành:

```text
✅ PHASE 1 — Lab
```

**Bây giờ chưa cần viết rule.**

Hãy làm theo đúng thứ tự:

```text
STEP 2.1
Raw Socket capture
        ↓
STEP 2.2
Ethernet decode
        ↓
STEP 2.3
IPv4 decode
        ↓
STEP 2.4
TCP/UDP/ICMP decode
        ↓
STEP 2.5
Packet object
        ↓
STEP 2.6
5-tuple Flow Key
        ↓
TEST
ping + nmap
```

Khi bạn nhìn được output kiểu:

```text
[TCP]
192.168.100.10:54321
        →
192.168.100.30:80

SEQ=123456
ACK=789012
FLAGS=SYN
PAYLOAD=...
```

thì **mới chuyển sang Flow Manager và TCP Reassembly**.

Đó cũng chính là lúc project của bạn bắt đầu đi từ **"packet sniffer" → "IDS engine"**.
