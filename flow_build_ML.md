Được. Với project của bạn, mình khuyên **ML phải là một module độc lập nằm sau IDS core**, không trộn ML vào signature engine ngay từ đầu.

Kiến trúc:

```text
                    NETWORK TRAFFIC
                           │
                           ▼
                 ┌───────────────────┐
                 │    IDS ENGINE     │
                 │                   │
                 │ Capture           │
                 │ Decode            │
                 │ Flow              │
                 │ Reassembly        │
                 │ Normalization     │
                 │ Signature Rules   │
                 │ Behavioral Rules  │
                 └─────────┬─────────┘
                           │
                           │ flow / traffic features
                           ▼
                 ┌───────────────────┐
                 │   ML PIPELINE     │
                 │                   │
                 │ Feature Extraction│
                 │ Dataset           │
                 │ Preprocessing     │
                 │ Training          │
                 │ Validation        │
                 │ Inference         │
                 └─────────┬─────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │  HYBRID DETECTOR  │
                 │                   │
                 │ Signature Alert   │
                 │ Behavioral Alert  │
                 │ ML Anomaly Alert  │
                 └─────────┬─────────┘
                           │
                           ▼
                       SIEM / SOC
```

Mình sẽ gọi version này là:

# ML-V1 — Network Anomaly Detection

Mục tiêu **không phải** làm "AI phát hiện mọi attack", mà là:

> Xây dựng một anomaly detection pipeline có khả năng học traffic bình thường và phát hiện những flow có hành vi bất thường mà signature rules chưa biết.

---

# PHASE ML-1 — Xác định bài toán

Trước khi viết ML, bạn phải xác định:

```text
Input:
Network Flow

Output:
Anomaly Score
+
Normal / Anomalous
```

Ví dụ:

```text
Flow #1234

src_ip          192.168.100.10
dst_ip          192.168.100.30
protocol        TCP
duration        2.1s
packets         85
bytes           12500
syn_count       3
rst_count       0
```

ML không nên nhận trực tiếp:

```text
raw packet bytes
```

ở version đầu.

Thay vào đó:

```text
Packet
   ↓
Flow
   ↓
Features
   ↓
ML
```

Đây là cách dễ kiểm soát và giải thích hơn.

---

# PHASE ML-2 — Xây Feature Extraction

Đây là bước **quan trọng nhất của ML-V1**.

Bạn cần tạo:

```text
FeatureExtractor
```

từ flow engine hiện tại.

Ví dụ một flow:

```text
192.168.100.10:54321
        ↓
192.168.100.30:80
```

sẽ được chuyển thành:

```text
[
    duration,
    packets,
    bytes,
    packets_per_second,
    bytes_per_second,
    src_bytes,
    dst_bytes,
    syn_count,
    ack_count,
    rst_count,
    fin_count,
    unique_dst_ports,
    payload_size_mean,
    payload_size_std
]
```

---

# ML-2.1 — Feature nhóm 1: Volume

Các feature đầu tiên:

```text
total_packets
total_bytes
src_packets
dst_packets
src_bytes
dst_bytes
```

Ví dụ:

```text
total_packets = 5000
total_bytes = 8,500,000
```

---

# ML-2.2 — Feature nhóm 2: Rate

Từ:

```text
duration
packets
bytes
```

tính:

```text
packet_rate
byte_rate
```

Ví dụ:

```text
packet_rate = packets / duration
```

Các feature:

```text
packets_per_second
bytes_per_second
```

Điều này cực kỳ hữu ích để phát hiện:

* flood
* scanning
* abnormal traffic bursts

---

# ML-2.3 — Feature nhóm 3: TCP behavior

Từ TCP flags:

```text
SYN
ACK
RST
FIN
PSH
URG
```

tạo:

```text
syn_count
ack_count
rst_count
fin_count
psh_count
```

Sau đó tạo ratio:

```text
syn_ratio
rst_ratio
ack_ratio
```

Ví dụ:

```text
syn_ratio =
SYN packets / total TCP packets
```

Một flow:

```text
1000 SYN
10 ACK
```

rất khác:

```text
10 SYN
950 ACK
```

---

# ML-2.4 — Feature nhóm 4: Packet size

Tính:

```text
payload_size_mean
payload_size_std
payload_size_min
payload_size_max
```

Ví dụ:

```text
mean = 120
std = 15
```

vs:

```text
mean = 1500
std = 700
```

---

# ML-2.5 — Feature nhóm 5: Connection behavior

Từ Flow Manager:

```text
unique_dst_ports
unique_dst_ips
connection_count
failed_connections
```

Đặc biệt:

```text
unique_dst_ports
```

rất hữu ích cho scan detection.

---

# ML-2.6 — Feature nhóm 6: Directionality

Ví dụ:

```text
src_bytes / dst_bytes
```

Tạo:

```text
upload_download_ratio
```

Một flow bình thường:

```text
client → server
1000 bytes
server → client
100000 bytes
```

khác rất nhiều với:

```text
client → server
5000000 bytes
server → client
500 bytes
```

---

# PHASE ML-3 — Xây Dataset

Đây là bước mà nhiều project ML IDS làm rất sơ sài.

Bạn **không nên bắt đầu bằng dataset trên Internet ngay**.

Hãy tạo dataset từ chính lab của bạn.

Kiến trúc:

```text
Kali
 │
 ├── normal traffic
 │
 ├── nmap
 │
 ├── ping flood
 │
 ├── HTTP attack
 │
 └── SQLMap
       │
       ▼
     IDS
       │
       ▼
Feature Extractor
       │
       ▼
CSV / Parquet
```

Ví dụ:

```text
network_features.csv
```

---

# PHASE ML-4 — Thu thập NORMAL traffic

Đây là bước đầu tiên.

Chạy traffic bình thường:

```text
ping
HTTP browsing
SSH
DNS
file transfer
```

Ví dụ:

```text
normal_001
normal_002
normal_003
...
normal_10000
```

Mục tiêu:

> Cho model biết "normal network" của lab trông như thế nào.

---

# PHASE ML-5 — Thu thập ATTACK traffic

Sau đó tạo:

```text
attack traffic
```

Ví dụ:

### Nmap

```bash
nmap -sS 192.168.100.30
```

### Port scan

```bash
nmap -p- 192.168.100.30
```

### HTTP attack

```text
SQL injection
XSS
command injection
```

### Flood

```text
ICMP burst
```

Bạn sẽ có:

```text
dataset/
├── normal/
└── attack/
```

---

# Nhưng ML-V1 không dùng attack labels để train

Đây là điểm mình khuyên bạn giữ.

Dùng:

> **Unsupervised Anomaly Detection**

Training:

```text
NORMAL TRAFFIC ONLY
```

Inference:

```text
normal
+
unknown attack
```

Vì mục tiêu là:

> Phát hiện những thứ IDS signature chưa biết.

---

# PHASE ML-6 — Dataset format

Ví dụ:

```csv
duration,total_packets,total_bytes,src_bytes,dst_bytes,packet_rate,byte_rate,syn_ratio,rst_ratio,payload_mean,payload_std,unique_dst_ports
1.2,50,8200,1200,7000,41.6,6833,0.02,0.00,164,31,1
2.1,80,12000,3000,9000,38.1,5714,0.01,0.00,150,28,1
0.3,2000,100000,90000,10000,6666,333333,0.98,0.01,50,10,45
```

Flow cuối rõ ràng rất khác.

---

# PHASE ML-7 — Preprocessing

Trước khi train:

```text
Raw features
     ↓
Missing values
     ↓
Invalid values
     ↓
Feature scaling
     ↓
ML matrix
```

Bạn có thể dùng:

```python
pandas
numpy
scikit-learn
```

---

# ML-7.1 — Loại bỏ feature không phù hợp

Không đưa:

```text
src_ip
dst_ip
timestamp
```

trực tiếp vào model V1.

Ví dụ:

```text
192.168.100.10
```

không phải behavior.

Nếu đưa IP vào model:

```text
Model:
192.168.100.10 = normal
```

thì model dễ học thuộc lab thay vì học hành vi.

---

# ML-7.2 — Scaling

Dùng:

```text
StandardScaler
```

Ví dụ:

```text
bytes = 1000000
packets = 500
syn_ratio = 0.98
```

có scale rất khác nhau.

Pipeline:

```text
Features
   ↓
StandardScaler
   ↓
Isolation Forest
```

---

# PHASE ML-8 — Model đầu tiên: Isolation Forest

Đây là model mình chọn cho V1.

Không cần neural network.

Không cần deep learning.

Không cần LSTM.

Không cần Transformer.

Architecture:

```text
NORMAL FLOW FEATURES
        │
        ▼
 StandardScaler
        │
        ▼
 Isolation Forest
        │
        ▼
Anomaly Score
```

Tại sao?

Isolation Forest rất phù hợp để làm baseline anomaly detection và có sẵn trong scikit-learn.

---

# PHASE ML-9 — Training

Concept:

```python
X_normal
    ↓
StandardScaler
    ↓
IsolationForest
    ↓
model.pkl
```

Bạn lưu:

```text
models/
├── scaler.pkl
└── isolation_forest.pkl
```

---

# PHASE ML-10 — Chọn contamination

Ví dụ:

```text
contamination = 0.01
```

nghĩa là bạn giả định một tỷ lệ nhỏ dữ liệu training có thể là anomaly.

Nhưng **đừng mặc định rằng 1% luôn đúng**.

Bạn cần thử:

```text
0.001
0.005
0.01
0.02
0.05
```

rồi đánh giá.

---

# PHASE ML-11 — Anomaly Score

Model trả về:

```text
anomaly score
```

Ví dụ:

```text
Flow A
score = +0.31
```

→ bình thường.

```text
Flow B
score = -0.42
```

→ suspicious.

Bạn tạo:

```text
ML threshold
```

Ví dụ:

```text
score < threshold
        ↓
ANOMALY
```

**Không nên hard-code threshold mà không đánh giá.**

Hãy xác định threshold dựa trên validation data.

---

# PHASE ML-12 — Tạo ML Detector

Tạo module:

```text
ml/
├── feature_extractor.py
├── preprocess.py
├── train.py
├── evaluate.py
├── inference.py
└── model/
```

Flow runtime:

```text
Flow
 │
 ▼
FeatureExtractor
 │
 ▼
Scaler
 │
 ▼
IsolationForest
 │
 ▼
score
 │
 ├── normal
 │
 └── anomaly
```

---

# PHASE ML-13 — Đưa ML vào IDS

Đây là thời điểm integration.

Không thay thế Rule Engine.

Mà:

```text
                   Flow
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
 Signature Engine            ML Engine
        │                         │
        ▼                         ▼
  Known Attack               Anomaly
        │                         │
        └────────────┬────────────┘
                     ▼
                Alert Engine
```

Ví dụ:

```text
Rule:
SQL Injection
     ↓
KNOWN ATTACK
```

ML:

```text
unusual traffic
     ↓
ANOMALY
```

---

# PHASE ML-14 — Hybrid Alert

Bạn nên mở rộng alert schema:

```json
{
  "@timestamp": "2026-08-03T10:20:00Z",

  "event": {
    "kind": "alert",
    "category": "network"
  },

  "source": {
    "ip": "192.168.100.10",
    "port": 54321
  },

  "destination": {
    "ip": "192.168.100.30",
    "port": 80
  },

  "detection": {
    "type": "ml_anomaly",
    "model": "isolation_forest",
    "score": -0.42
  }
}
```

Nếu signature:

```json
{
  "detection": {
    "type": "signature",
    "rule_id": 10004,
    "name": "SQL_INJECTION_UNION_SELECT"
  }
}
```

---

# PHASE ML-15 — Đánh giá model

Đây là phần **bắt buộc**.

Không được chỉ nói:

> "Accuracy 95%."

Với anomaly detection, accuracy có thể rất misleading.

Bạn cần:

```text
Precision
Recall
F1
False Positive Rate
Detection Rate
```

Đặc biệt:

### False Positive

```text
Normal traffic
      ↓
ML
      ↓
ANOMALY
```

Đây là vấn đề cực lớn trong SOC.

Nếu:

```text
1000 normal flows
100 false alerts
```

thì SOC sẽ rất khó sử dụng.

---

# PHASE ML-16 — Confusion Matrix

Sau khi có attack dataset:

```text
                    Predicted
                 Normal   Anomaly

Actual Normal      TN       FP

Actual Attack      FN       TP
```

Bạn cần đặc biệt quan tâm:

```text
FP
FN
```

---

# PHASE ML-17 — So sánh Rule vs ML

Đây sẽ là phần **rất đẹp trong report/CV**.

Tạo bảng:

| Attack          | Signature IDS | ML | Hybrid |
| --------------- | ------------: | -: | -----: |
| SQL Injection   |             ✅ |  ? |      ✅ |
| XSS             |             ✅ |  ? |      ✅ |
| Nmap Scan       |             ✅ |  ? |      ✅ |
| ICMP Flood      |             ✅ |  ? |      ✅ |
| Unknown anomaly |             ❌ |  ✅ |      ✅ |

Mục tiêu của ML:

> Không cạnh tranh với signature engine.

Mà:

> **Bổ sung detection capability cho các hành vi chưa có signature.**

---

# PHASE ML-18 — Test "Unknown Attack"

Đây là experiment quan trọng nhất của ML-V1.

Training:

```text
NORMAL
```

Không cho model thấy:

```text
DNS tunneling
```

Sau đó chạy DNS tunneling.

Flow:

```text
Normal dataset
      ↓
Train
      ↓
Isolation Forest
      ↓
DNS tunneling traffic
      ↓
ANOMALY ?
```

Nếu có:

> Bạn đã chứng minh được concept **unknown/anomalous behavior detection**.

Nhưng nhớ:

**Đừng gọi nó là "zero-day detection" một cách tuyệt đối.**

Nên nói:

> **anomaly detection for previously unseen traffic patterns**

chính xác hơn.

---

# PHASE ML-19 — Explainability

Đây là bước mình **rất khuyến khích bạn làm** vì nó phù hợp hướng Security Engineer.

Thay vì:

```text
ANOMALY
score = -0.42
```

hãy cho:

```text
ANOMALY DETECTED

Reason:
- packet rate: 6800 pkt/s
- SYN ratio: 0.97
- unique destination ports: 45
- byte rate: 320 KB/s

Anomaly score:
-0.42
```

Bạn có thể xây:

```text
Feature contribution / reason engine
```

dù Isolation Forest không trực tiếp cho bạn một "reason" hoàn hảo.

Đây sẽ biến:

> ML black box

thành:

> **SOC-useful detection.**

---

# PHASE ML-20 — ML Dashboard

Dashboard của bạn có thể có:

```text
┌─────────────────────────────────────────────┐
│             IDS SECURITY DASHBOARD          │
├─────────────────────────────────────────────┤
│                                             │
│  Signature Alerts       127                 │
│  Behavioral Alerts       42                 │
│  ML Anomalies            18                 │
│                                             │
├─────────────────────────────────────────────┤
│                                             │
│             Traffic Anomaly                │
│                                             │
│   ────────────────╮                        │
│                   ╰──────╮                 │
│                          ●                  │
│                          ↑                  │
│                     anomaly                │
│                                             │
├─────────────────────────────────────────────┤
│ Top ML anomalies                            │
│                                             │
│ 10:32  192.168.100.10  -0.42               │
│ 10:34  192.168.100.15  -0.37               │
│ 10:41  192.168.100.22  -0.31               │
└─────────────────────────────────────────────┘
```

---

# PHASE ML-21 — Offline vs Online Inference

ML-V1 nên:

### Training

Offline:

```text
Dataset
   ↓
train.py
   ↓
model.pkl
```

### Detection

Online:

```text
Live traffic
    ↓
IDS
    ↓
Flow
    ↓
Features
    ↓
model.pkl
    ↓
Prediction
```

**Không train model ngay trên live traffic trong V1.**

---

# PHASE ML-22 — ML-V1 Folder Architecture

Sau khi hoàn thành, project của bạn có thể thành:

```text
ids/
│
├── capture/
│   └── packet_capture.py
│
├── decoder/
│   ├── ethernet.py
│   ├── ipv4.py
│   ├── tcp.py
│   └── udp.py
│
├── flow/
│   ├── flow.py
│   ├── manager.py
│   └── tcp_state.py
│
├── reassembly/
│   ├── ip_fragment.py
│   └── tcp_stream.py
│
├── normalization/
│   ├── url.py
│   └── http.py
│
├── detection/
│   ├── rule_engine.py
│   ├── signature.py
│   ├── behavioral.py
│   └── aho_corasick.py
│
├── rules/
│   ├── web.yaml
│   ├── network.yaml
│   └── scan.yaml
│
├── alert/
│   ├── alert.py
│   └── ecs.py
│
├── ml/
│   ├── features.py
│   ├── dataset.py
│   ├── preprocess.py
│   ├── train.py
│   ├── evaluate.py
│   ├── inference.py
│   │
│   └── models/
│       ├── scaler.pkl
│       └── isolation_forest.pkl
│
├── output/
│   └── alerts.json
│
└── main.py
```

---

# PHASE ML-23 — Thứ tự implementation thực tế

Đây là checklist mình khuyên bạn **bám đúng**:

```text
ML-V1

[ ] ML-01 Define ML objective
       ↓
[ ] ML-02 Design feature schema
       ↓
[ ] ML-03 Implement FeatureExtractor
       ↓
[ ] ML-04 Export flow → CSV
       ↓
[ ] ML-05 Collect normal traffic
       ↓
[ ] ML-06 Collect attack traffic
       ↓
[ ] ML-07 Clean dataset
       ↓
[ ] ML-08 Train/test split
       ↓
[ ] ML-09 StandardScaler
       ↓
[ ] ML-10 Isolation Forest
       ↓
[ ] ML-11 Tune contamination
       ↓
[ ] ML-12 Determine threshold
       ↓
[ ] ML-13 Evaluate
       ↓
[ ] ML-14 Build inference.py
       ↓
[ ] ML-15 Connect to live IDS
       ↓
[ ] ML-16 Generate ML alerts
       ↓
[ ] ML-17 Hybrid signature + ML
       ↓
[ ] ML-18 Unknown attack experiment
       ↓
[ ] ML-19 Explain anomaly
       ↓
[ ] ML-20 Dashboard
       ↓
[ ] ML-21 Benchmark
```

---

# PHASE ML-24 — Sau ML-V1 bạn sẽ có gì?

Khi hoàn thành toàn bộ IDS + ML-V1:

```text
                   NETWORK
                      │
                      ▼
                PACKET CAPTURE
                      │
                      ▼
                   DECODER
                      │
                      ▼
                 FLOW ENGINE
                      │
                      ▼
                REASSEMBLY
                      │
                      ▼
                NORMALIZATION
                      │
             ┌────────┴─────────┐
             │                  │
             ▼                  ▼
      SIGNATURE ENGINE      ML ENGINE
             │                  │
       Known attacks       Anomalies
             │                  │
             └────────┬─────────┘
                      ▼
                 ALERT ENGINE
                      │
                      ▼
                    SIEM
```

Và lúc này project của bạn có **hai lớp detection**:

### Layer 1 — Deterministic

```text
Snort-style
Signature
Rule
Pattern
Threshold
```

→ **Known attacks**

### Layer 2 — Statistical

```text
Feature
Model
Anomaly Score
```

→ **Previously unseen / unusual behavior**

Đây là architecture hợp lý hơn rất nhiều so với việc nhét ML trực tiếp vào packet-level IDS.

---

## Và mình khuyên bạn chưa cần Deep Learning

ML-V1 chỉ cần:

```text
Python
Pandas
NumPy
Scikit-learn
Joblib
Matplotlib
```

với:

```text
Isolation Forest
```

là đủ.

Sau này nếu bạn muốn làm **ML-V2**, lúc đó mới mở rộng:

```text
ML-V1
Isolation Forest
      ↓
ML-V2
Random Forest / XGBoost
      ↓
ML-V3
Autoencoder
      ↓
ML-V4
Online / Streaming Detection
      ↓
ML-V5
Hybrid AI + Rule Engine
```

Như vậy project của bạn sẽ có một progression rất đẹp:

```text
V1  Packet Sniffer
        ↓
V2  Network IDS
        ↓
V3  Anti-Evasion IDS
        ↓
V4  High-Performance IDS
        ↓
V5  ML Anomaly Detection
        ↓
V6  Hybrid IDS
        ↓
V7  SIEM/SOC Integration
```

**Quan trọng nhất:** ML chỉ nên bắt đầu **sau khi IDS core của bạn đã có Flow Manager + TCP Reassembly + Rule Engine + Alert Engine**. Khi đó bạn có sẵn một nguồn flow/feature rất tốt, thay vì phải xây một hệ thống ML tách biệt từ đầu.
