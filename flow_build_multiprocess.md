Đúng. Với project của bạn, **Multiprocessing nên là một version riêng sau khi IDS single-process đã chạy ổn định**, chứ không nên đưa vào từ đầu. Vì bạn dùng Python, mục tiêu của version này là giải quyết **GIL + tăng throughput**, nhưng quan trọng hơn là chứng minh bạn hiểu cách thiết kế pipeline IDS có concurrency.

Mình sẽ đặt nó là **IDS-V5: Multi-Process High-Performance Engine**, sau ML thì thành một nhánh riêng.

---

# 1. Vị trí của Multiprocessing trong toàn bộ roadmap

Mình đề xuất roadmap cuối cùng:

```text
IDS-V1
Lab + Packet Capture
        ↓
IDS-V2
Packet Decoder + Flow Engine
        ↓
IDS-V3
Reassembly + Anti-Evasion
        ↓
IDS-V4
Rule Engine + Detection + Alert
        ↓
IDS-V5
MULTI-PROCESS IDS
        ↓
IDS-V6
SIEM / Dashboard
        ↓
ML-V1
Anomaly Detection
        ↓
ML-V2+
Advanced ML
```

Tuy nhiên có một điểm:

**ML có thể làm trước hoặc sau V6**, vì ML không phụ thuộc trực tiếp vào multiprocessing.

Với mục tiêu học của bạn, mình thích:

```text
Single-process IDS
        ↓
Multi-process IDS
        ↓
SIEM
        ↓
ML
        ↓
Hybrid IDS
```

---

# 2. Mục tiêu của Multi-Process Version

Không phải:

> "Dùng multiprocessing vì Python chậm."

Mà là:

> **Tách các workload độc lập của IDS thành các process có thể chạy song song trên nhiều CPU cores.**

Pipeline:

```text
                         NETWORK
                            │
                            ▼
                  ┌───────────────────┐
                  │ PROCESS 1         │
                  │ PACKET CAPTURE    │
                  │                   │
                  │ Raw Socket        │
                  │ Decode            │
                  └─────────┬─────────┘
                            │
                       Queue / IPC
                            │
                            ▼
                  ┌───────────────────┐
                  │ PROCESS 2         │
                  │ FLOW + REASSEMBLY │
                  │                   │
                  │ Flow Manager      │
                  │ TCP Reassembly    │
                  │ IP Reassembly     │
                  └─────────┬─────────┘
                            │
                       Queue / IPC
                            │
                            ▼
                  ┌───────────────────┐
                  │ PROCESS 3         │
                  │ DETECTION         │
                  │                   │
                  │ Aho-Corasick      │
                  │ Regex             │
                  │ Behavioral        │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │ PROCESS 4         │
                  │ ALERT / LOGGING   │
                  │                   │
                  │ JSON / ECS        │
                  └───────────────────┘
```

---

# 3. Nhưng có một vấn đề cực kỳ quan trọng

Bạn **không thể chia packet tùy ý cho nhiều process**.

Ví dụ:

```text
Packet 1 → Process 2A
Packet 2 → Process 2B
Packet 3 → Process 2A
```

Nếu:

```text
Packet 1
SEQ = 1000
```

đi Process 2A,

nhưng:

```text
Packet 2
SEQ = 1500
```

đi Process 2B,

thì TCP stream state bị chia đôi.

→ Reassembly sai.

Vì vậy bạn cần:

# Flow Affinity

Các packet của **cùng một flow phải luôn đi vào cùng worker**.

---

# 4. Flow Affinity

Ví dụ:

```text
Flow A
192.168.100.10:5000
        ↓
192.168.100.30:80
```

luôn:

```text
Worker 1
```

Flow B:

```text
192.168.100.10:5001
        ↓
192.168.100.30:80
```

có thể:

```text
Worker 2
```

Ta hash:

```python
worker_id = hash(flow_key) % num_workers
```

Ví dụ:

```text
flow_key
    ↓
hash()
    ↓
worker_id
```

---

# 5. Đây là kiến trúc mình khuyên bạn dùng

Thay vì:

```text
Capture
  ↓
Queue
  ↓
Reassembly Worker 1
Reassembly Worker 2
Reassembly Worker 3
```

hãy:

```text
                       CAPTURE
                          │
                          ▼
                   FLOW HASHER
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
          Worker 1     Worker 2     Worker 3
             │            │            │
             ▼            ▼            ▼
          Reassembly   Reassembly   Reassembly
             │            │            │
             ▼            ▼            ▼
          Detection    Detection    Detection
             │            │            │
             └────────────┼────────────┘
                          ▼
                    ALERT PROCESS
```

Như vậy mỗi worker có state riêng.

---

# 6. MULTIPROCESS-V1 — Process architecture cơ bản

Đầu tiên chỉ cần:

```text
Process 1
Capture

Process 2
Detection

Process 3
Logging
```

Flow:

```text
Capture
   ↓
multiprocessing.Queue
   ↓
Detection
   ↓
multiprocessing.Queue
   ↓
Logger
```

Đừng ngay lập tức tạo 10 workers.

---

# 7. Step MP-01 — Tạo IPC Queue

Bạn sử dụng:

```python
from multiprocessing import Process, Queue
```

Kiến trúc:

```text
Capture Process
      │
      │ packet_queue
      ▼
Detection Process
      │
      │ alert_queue
      ▼
Logger Process
```

---

# 8. Step MP-02 — Capture Process

Process này chỉ làm:

```text
RAW PACKET
    ↓
DECODE
    ↓
Packet Object
    ↓
Queue
```

Không làm:

```text
❌ Rule detection
❌ Logging
❌ ML
❌ Heavy processing
```

Mục tiêu:

> Capture process phải càng nhẹ càng tốt.

---

# 9. Step MP-03 — Detection Process

Process nhận:

```text
Packet
```

sau đó:

```text
Packet
 ↓
Flow Manager
 ↓
Reassembly
 ↓
Normalization
 ↓
Detection
```

Ở version đầu, **toàn bộ detection state nằm trong process này**.

---

# 10. Step MP-04 — Logger Process

Logger nhận:

```text
Alert
```

và xử lý:

```text
Alert
 ↓
ECS
 ↓
JSON
 ↓
alerts.json
```

Điều này rất quan trọng.

Nếu detection process tự ghi file:

```text
Worker 1 → write
Worker 2 → write
Worker 3 → write
```

bạn dễ gặp:

```text
race condition
log corruption
locking
```

Tách logger process sẽ sạch hơn.

---

# 11. MULTIPROCESS-V2 — Multiple Detection Workers

Sau khi V1 chạy ổn:

```text
Capture
   ↓
Dispatcher
   │
   ├── Worker 1
   ├── Worker 2
   ├── Worker 3
   └── Worker 4
```

Nhưng nhớ:

> **Dispatch theo flow affinity.**

Không phải round-robin:

```text
❌ Packet 1 → Worker 1
❌ Packet 2 → Worker 2
❌ Packet 3 → Worker 3
```

Mà:

```text
Flow A → Worker 1
Flow A → Worker 1
Flow A → Worker 1

Flow B → Worker 2
Flow B → Worker 2
```

---

# 12. MULTIPROCESS-V3 — Worker Architecture

Mỗi worker:

```text
Worker
│
├── Flow Table
│
├── TCP Reassembly
│
├── IP Reassembly
│
├── Normalizer
│
├── Signature Engine
│
└── Behavioral Engine
```

Ví dụ:

```text
Worker 1

Flow A
Flow B
Flow C
Flow D

       ↓

Reassembly

       ↓

Aho-Corasick

       ↓

Behavior Detection
```

---

# 13. Step MP-05 — Worker Pool

Bạn có thể sử dụng:

```python
multiprocessing.Process
```

thay vì phụ thuộc ngay vào:

```python
multiprocessing.Pool
```

Vì IDS cần **long-running stateful workers**.

Concept:

```text
workers = [
    Worker 1,
    Worker 2,
    Worker 3,
    Worker 4
]
```

---

# 14. Step MP-06 — Dispatcher

Dispatcher:

```text
Packet
   ↓
Extract 5-tuple
   ↓
hash(flow_key)
   ↓
worker_id
   ↓
worker_queue[worker_id]
```

Ví dụ:

```text
Flow A
hash = 1234
1234 % 4 = 2

→ Worker 2
```

---

# 15. Step MP-07 — Backpressure

Đây là một phần rất đáng đưa vào project.

Giả sử:

```text
Capture
  ↓
10,000 packets/sec
```

nhưng:

```text
Detection
  ↓
5,000 packets/sec
```

Queue sẽ:

```text
100
500
1000
5000
10000
...
```

→ RAM tăng.

Bạn cần:

```text
Bounded Queue
```

Ví dụ concept:

```text
Queue(maxsize=10000)
```

Khi queue đầy, bạn phải quyết định:

```text
drop packet?
block capture?
sample?
```

Đây là một vấn đề **rất thực tế của IDS**.

---

# 16. Step MP-08 — Packet Drop Counter

Bạn nên thêm:

```text
packets_received
packets_processed
packets_dropped
queue_overflow
```

Ví dụ:

```text
────────────────────────
IDS PERFORMANCE
────────────────────────
Received:       1,000,000
Processed:        998,420
Dropped:            1,580
Drop rate:           0.158%
────────────────────────
```

Đây là dữ liệu cực kỳ giá trị khi benchmark.

---

# 17. MULTIPROCESS-V4 — Shared Memory

Sau Queue, bạn có thể thử:

```text
multiprocessing.shared_memory
```

Nhưng **đây là optional advanced step**.

Vấn đề:

```text
Queue
```

có serialization / IPC overhead.

Packet:

```text
Python Object
```

được truyền giữa process → có overhead.

Shared memory có thể giảm một phần overhead.

Architecture:

```text
Capture
   │
   ▼
Shared Memory Buffer
   │
   ▼
Workers
```

Nhưng mình **không khuyên bạn dùng ngay**.

Hãy benchmark Queue trước.

---

# 18. MULTIPROCESS-V5 — Zero-copy / Ring Buffer

Nếu muốn đẩy project lên mức advanced:

```text
Capture
   ↓
Ring Buffer
   ↓
Workers
```

Concept:

```text
┌──────────────────────────────┐
│        RING BUFFER           │
│                              │
│ [P1][P2][P3][P4][P5][P6]    │
│   ↑                    ↑     │
│ reader              writer   │
└──────────────────────────────┘
```

Nhưng đây đã bắt đầu đi vào:

> high-performance packet processing

và không cần thiết cho MVP.

---

# 19. MULTIPROCESS-V6 — CPU Affinity

Sau khi benchmark:

```text
Worker 1 → CPU 1
Worker 2 → CPU 2
Worker 3 → CPU 3
Worker 4 → CPU 4
```

Có thể dùng CPU affinity trên Linux.

Mục tiêu:

```text
Capture
→ dedicated CPU

Detection Worker 1
→ CPU 1

Detection Worker 2
→ CPU 2
```

Đây là optimization nâng cao.

---

# 20. MULTIPROCESS-V7 — Benchmark

Đây mới là **đích cuối của Multiprocessing Version**.

Bạn phải so sánh:

### Single Process

```text
1 Process
```

với:

### Multi Process

```text
1 Capture
+
2 Workers
```

và:

```text
1 Capture
+
4 Workers
```

---

# 21. Các metric cần đo

## Throughput

```text
packets/sec
MB/sec
```

---

## Latency

```text
packet arrival
        ↓
alert generated
```

Ví dụ:

```text
Detection latency = 3.2 ms
```

---

## CPU

```text
CPU utilization
per process
```

---

## Memory

```text
RSS
Queue memory
Worker memory
```

---

## Packet loss

```text
received
processed
dropped
```

---

## Detection accuracy

Cực kỳ quan trọng:

```text
Single-process:
100 attacks
→ 100 detected

Multi-process:
100 attacks
→ 100 detected
```

Nếu multiprocessing nhanh hơn nhưng mất detection:

> ❌ Không đạt.

---

# 22. Test matrix

Bạn có thể làm bảng:

| Architecture | Workers | Throughput | Drop Rate | Latency |
| ------------ | ------: | ---------: | --------: | ------: |
| Single       |       1 |          X |         X |       X |
| Multi        |       2 |          X |         X |       X |
| Multi        |       4 |          X |         X |       X |
| Multi        |       8 |          X |         X |       X |

Sau đó vẽ:

```text
Throughput
   │
   │                 ●
   │           ●
   │      ●
   │ ●
   └──────────────────────
       1   2   4   8
          Workers
```

Bạn sẽ biết:

> thêm worker có thực sự tăng performance hay không.

---

# 23. Folder structure sau khi thêm Multiprocessing

Project của bạn lúc đó:

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
│   ├── udp.py
│   └── icmp.py
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
│   └── normalizer.py
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
├── multiprocessing_engine/
│   ├── capture_process.py
│   ├── dispatcher.py
│   ├── worker.py
│   ├── logger_process.py
│   ├── queues.py
│   ├── affinity.py
│   └── metrics.py
│
├── ml/
│   ├── features.py
│   ├── train.py
│   ├── evaluate.py
│   └── inference.py
│
├── benchmarks/
│   ├── benchmark_single.py
│   ├── benchmark_multi.py
│   └── results/
│
└── main.py
```

---

# 24. Toàn bộ Multiprocessing Roadmap

Bạn có thể copy nguyên checklist này vào Notion:

```text
MULTIPROCESSING VERSION
────────────────────────────────────

MP-01
□ Refactor IDS into independent modules

MP-02
□ Create Capture Process

MP-03
□ Create Detection Process

MP-04
□ Create Logger Process

MP-05
□ multiprocessing.Queue

MP-06
□ Packet IPC format

MP-07
□ Alert IPC format

MP-08
□ Graceful shutdown

MP-09
□ Process monitoring

MP-10
□ Bounded Queue

MP-11
□ Backpressure handling

MP-12
□ Packet drop counter

MP-13
□ Flow affinity

MP-14
□ Dispatcher

MP-15
□ Multiple detection workers

MP-16
□ Per-worker Flow Table

MP-17
□ Per-worker TCP reassembly

MP-18
□ Per-worker detection state

MP-19
□ Central Alert Logger

MP-20
□ Performance metrics

MP-21
□ CPU monitoring

MP-22
□ Memory monitoring

MP-23
□ Throughput benchmark

MP-24
□ Detection latency benchmark

MP-25
□ Packet drop benchmark

MP-26
□ Compare 1 vs 2 vs 4 workers

MP-27
□ Shared Memory experiment

MP-28
□ CPU affinity experiment

MP-29
□ Stress test

MP-30
□ Document architecture
```

---

# 25. Version này kết hợp với ML của bạn như thế nào?

Cuối cùng bạn sẽ có:

```text
                         NETWORK
                            │
                            ▼
                    ┌──────────────┐
                    │ CAPTURE      │
                    │ PROCESS      │
                    └──────┬───────┘
                           │
                     FLOW HASH
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
          WORKER 1      WORKER 2      WORKER 3
             │             │             │
             ▼             ▼             ▼
         REASSEMBLY     REASSEMBLY     REASSEMBLY
             │             │             │
             ▼             ▼             ▼
          RULE + ML     RULE + ML     RULE + ML
             │             │             │
             └─────────────┼─────────────┘
                           ▼
                    ALERT PROCESS
                           │
                           ▼
                         ECS
                           │
                    ┌──────┴──────┐
                    ▼             ▼
                   SIEM        Dashboard
```

Như vậy **ML cũng chạy trong detection worker**, nhưng mỗi worker có model đã load sẵn trong memory:

```text
Worker 1
 ├── Rule Engine
 └── ML Model

Worker 2
 ├── Rule Engine
 └── ML Model

Worker 3
 ├── Rule Engine
 └── ML Model
```

Không nên để mỗi packet phải load:

```text
model.pkl
```

Đó sẽ là một lỗi performance lớn.

Model phải được load **một lần khi worker khởi động**.

---

# 26. Một điểm rất quan trọng cho project của bạn

Nếu mục tiêu của bạn là **Cloud Security Engineer / Security Engineer**, mình không nghĩ bạn cần biến project thành một "Snort clone" với hàng triệu packet/s.

Điểm mạnh của project nên là:

```text
Networking
      +
Systems Programming
      +
Detection Engineering
      +
Anti-Evasion
      +
Concurrency
      +
ML
      +
SIEM
```

Đây là combination rất tốt để thể hiện năng lực.

Đặc biệt, phần **Multiprocessing + Flow Affinity + TCP Reassembly** sẽ cho thấy bạn không chỉ biết dùng Python để viết một packet sniffer, mà hiểu vấn đề **stateful network processing trong hệ thống IDS**.

Và khi kết hợp với ML-V1, câu chuyện project của bạn sẽ rất rõ:

```text
              CUSTOM NETWORK IDS

                 Layer 1
              Packet Engine
                    ↓
                 Layer 2
              Flow Engine
                    ↓
                 Layer 3
            Anti-Evasion Engine
                    ↓
                 Layer 4
           Signature Detection
                    ↓
                 Layer 5
          Behavioral Detection
                    ↓
                 Layer 6
            ML Anomaly Detection
                    ↓
                 Layer 7
             Multi-Process Engine
                    ↓
                 Layer 8
              SIEM / SOC
```

**Thứ tự implementation mình khuyên bạn:** hoàn thành **Single-process IDS → Multiprocessing → SIEM → ML → Hybrid IDS**. Như vậy mỗi version đều có thể benchmark và chứng minh được một năng lực kỹ thuật riêng, thay vì project trở thành một khối code lớn khó debug.
