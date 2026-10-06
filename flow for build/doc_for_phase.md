Dưới đây là toàn bộ tài liệu hướng dẫn học tập, đọc hiểu kỹ thuật và danh sách documentation chính thức được thiết kế lại **chuẩn hóa theo đúng kiến trúc High-Performance & Anti-Evasion IDS (Python + C-Extensions)** mà chúng ta đã thống nhất.

---

### Chi tiết từng giai đoạn + tài liệu & Technical Docs

#### **Giai đoạn 0 — Nền tảng Mạng & Lập trình Hệ thống (Networking & Systems Foundations)**

* **Kiến thức cần đọc:**
* Mô hình OSI/TCP-IP, cấu trúc chi tiết của Ethernet Header, IP Header, TCP Header (Sequence/Acknowledgment Number, TCP Flags, Window Size).
* Cơ chế hoạt động của Socket tầng OS, Linux Kernel Network Stack, Promiscuous Mode.
* Khái niệm về Bộ nhớ (Buffer, Pointers) và Tối ưu hóa I/O trong Python.


* **Sách & Tài liệu tham khảo:**
* *Computer Networking: A Top-Down Approach* — Kurose & Ross (Chương 2, 3, 4).
* *Linux System Programming* — Robert Love (Chương về Network I/O & Memory Management).
* Wireshark User's Guide: [https://www.wireshark.org/docs/wsug_html_chunked/](https://www.wireshark.org/docs/wsug_html_chunked/)


* **Thực hành:** Mở Wireshark, bắt luồng HTTP/TCP bất kỳ, phân tích thủ công chỉ số `Sequence Number` và `Acknowledgment Number` qua từng gói tin để hiểu cách TCP ghép luồng.

---

#### **Giai đoạn 1 — Kiến trúc IDS/IPS & Các Kỹ thuật Né tránh (Evasion Techniques)**

* **Kiến thức cần đọc:**
* Sự khác biệt giữa Out-of-band (IDS) và Inline (IPS).
* Các phương pháp Evasion nguy hiểm: **IP Fragmentation Attacks** (Teardrop, Overlapping fragments), **TCP Stream Splitting** (xé nhỏ payload), **URL/Hex Encoding**, **Case Confusion**.
* Cách các IDS lớn (Snort 3, Suricata) giải quyết bài toán Stream Reassembly.


* **Tài liệu kỹ thuật:**
* NIST SP 800-94 — Guide to IDPS: [https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-94.pdf](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-94.pdf)
* Luận văn "Analysis of Security Configuration for IDS/IPS" — Đặc biệt chương 2.2 và chương 11 (Cơ chế Preprocessors của Snort).
* Snort 3 Architecture Manual: [https://docs.snort.org/](https://docs.snort.org/)
* *Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection* — Ptacek & Newsham (Bài báo kinh điển về Anti-Evasion).



---

#### **Giai đoạn 2 — Packet Capture Tốc độ cao & C-Binding Parsing (Performance Engine)**

* **Kiến thức cần đọc:**
* Tại sao `Scapy` quá chậm (do overhead tạo Python Object) và cách thay thế bằng `Raw Socket` + `dpkt`.
* Cách đọc trực tiếp mảng `bytes` thô từ Linux Network Interface.
* Kỹ thuật ép kiểu Binary Struct bằng C-bindings trong Python.


* **Documentation chính thức:**
* Python `socket` Low-level networking interface: [https://docs.python.org/3/library/socket.html](https://docs.python.org/3/library/socket.html)
* `dpkt` Documentation (Fast packet parsing): [https://dpkt.readthedocs.io/en/latest/](https://dpkt.readthedocs.io/en/latest/)
* `pcapy-ng` Documentation (Nếu muốn dùng libpcap wrapper): [https://github.com/kisom/pcapy-ng](https://www.google.com/search?q=https://github.com/kisom/pcapy-ng)
* *Black Hat Python* — Justin Seitz (Chương 3: Network Sniffing với Raw Sockets).


* **Thực hành:** Viết script dùng Raw Socket + `dpkt` parse 100.000 gói tin/giây mà không bị drop gói tin nào.

---

#### **Giai đoạn 3 — Xây dựng Engine Anti-Evasion (IP Defrag & TCP Reassembly)**

* **Kiến thức cần đọc:**
* Thiết kế thuật toán gom mảnh IP (IP Defragmentation) dựa trên IP ID và Fragment Offset.
* Thiết kế thuật toán TCP Stream Reassembly: Quản lý Session Table bằng Hash Map (5-tuple), sắp xếp buffer theo TCP Sequence Number, xử lý gói tin Out-of-Order và Overlapping.
* Thuật toán Normalization: URL Unescaping (`urllib.parse`), Lowercasing, Path Normalization.


* **Documentation chính thức & RFCs:**
* RFC 791 (Internet Protocol) — Phần IP Fragmentation: [https://datatracker.ietf.org/doc/html/rfc791](https://datatracker.ietf.org/doc/html/rfc791)
* RFC 9293 (Transmission Control Protocol) — Phần Sequence Numbers & Reassembly: [https://datatracker.ietf.org/doc/html/rfc9293](https://datatracker.ietf.org/doc/html/rfc9293)
* Python `urllib.parse` Docs: [https://docs.python.org/3/library/urllib.parse.html](https://docs.python.org/3/library/urllib.parse.html)


* **Thực hành:** Viết Unit Test giả lập 3 gói TCP bị cắt lẻ (`UNI`, `ON SE`, `LECT`) gửi không đúng thứ tự $\rightarrow$ Engine tự xếp lại và xuất chuỗi hoàn chỉnh `UNION SELECT`.

---

#### **Giai đoạn 4 — So khớp Mẫu $O(N)$ bằng C-Extension & Behavior Tracking**

* **Kiến thức cần đọc:**
* Lý thuyết thuật toán **Aho-Corasick** (Trie-based Automaton) và lý do nó đạt tốc độ $O(N)$ bất kể số lượng Rule.
* Cấu trúc file luật YAML/JSON chuẩn hóa.
* Trạng thái bộ nhớ (State Tracking) để đếm tần suất packet/giây (bắt Port Scan, SYN Flood).


* **Documentation chính thức:**
* `pyahocorasick` Documentation (Intel C-Extension implementation): [https://pyahocorasick.readthedocs.io/en/latest/](https://pyahocorasick.readthedocs.io/en/latest/)
* `hyperscan` Python bindings (Intel Hyperscan - nếu muốn dùng Regex siêu tốc): [https://pypi.org/project/hyperscan/](https://pypi.org/project/hyperscan/)
* Snort Rule Writing Guide (để học cách tư duy viết luật): [https://docs.snort.org/rules/](https://www.google.com/search?q=https%3A%2F%2Fdocs.snort.org%2Frules%2F)


* **Thực hành:** Nạp 5.000 từ khóa tấn công vào `pyahocorasick` và đo thời gian scan 10MB payload (phải dưới 5 millisecond).

---

#### **Giai đoạn 5 — Tối ưu Đa nhân (Multi-processing) & Chuẩn hóa Logging (ECS)**

* **Kiến thức cần đọc:**
* Bản chất của Python **GIL (Global Interpreter Lock)** và lý do phải dùng `multiprocessing` thay vì `threading`.
* Kiến trúc IPC (Inter-Process Communication): `multiprocessing.Queue` và `SharedMemory`.
* Chuẩn hóa dữ liệu log theo **Elastic Common Schema (ECS)**.


* **Documentation chính thức:**
* Python `multiprocessing` Docs: [https://docs.python.org/3/library/multiprocessing.html](https://docs.python.org/3/library/multiprocessing.html)
* Elastic Common Schema (ECS) Reference: [https://www.elastic.co/guide/en/ecs/current/ecs-reference.html](https://www.google.com/search?q=https%3A%2F%2Fwww.elastic.co%2Fguide%2Fen%2Fecs%2Fcurrent%2Fecs-reference.html)
* Python `json` & `logging` Docs: [https://docs.python.org/3/library/logging.html](https://docs.python.org/3/library/logging.html)


* **Thực hành:** Tách hệ thống thành 3 Process độc lập (Capturer $\rightarrow$ Reassembler $\rightarrow$ Engine) giao tiếp qua Queue và ghi log JSON chuẩn ECS.

---

#### **Giai đoạn 6 — Lab Thực chiến, Evasion Testing & SIEM Integration**

* **Kiến thức cần đọc:**
* Kịch bản test tấn công mạng thực tế.
* Cách cấu hình đẩy Log JSON từ file vào SIEM (Wazuh hoặc Elastic Stack / ELK).


* **Công cụ & Documentation:**
* Kali Linux Tools: `nmap`, `hydra`, `sqlmap`, `hping3` (dùng để test SYN flood & fragmentation).
* TryHackMe (Lab "Nmap", "Snort", "Network Analysis"): [https://tryhackme.com/](https://tryhackme.com/)
* Wazuh Log Data Collection Docs: [https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/](https://www.google.com/search?q=https%3A%2F%2Fdocumentation.wazuh.com%2Fcurrent%2Fuser-manual%2Fcapabilities%2Flog-data-collection%2F)
* *Practical Packet Analysis* — Chris Sanders.


* **Thực hành:** Dùng `sqlmap` với cờ `--tamper=space2comment` và `nmap -f` tấn công Target $\rightarrow$ Đảm bảo IDS tự viết phát hiện được và xuất Log đẩy về Kibana/Wazuh Dashboard.

---

#### **Giai đoạn 7 — Tích hợp Machine Learning cho Anomaly Detection (Zero-Day Detection)**

* **Kiến thức cần đọc:**
* Trích xuất Flow Features từ Network Streams (Duration, Packet Rate, Byte Rate, Flow Packets/s, SYN Ratio).
* Mô hình học không giám sát (Unsupervised Learning) để phát hiện bất thường: **Isolation Forest**, **One-Class SVM**.


* **Dataset & Documentation:**
* `scikit-learn` User Guide: [https://scikit-learn.org/stable/user_guide.html](https://www.google.com/search?q=https%3A%2F%2Fscikit-learn.org%2Fstable%2Fuser_guide.html)
* CICIDS2017 / UNSW-NB15 Datasets: [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.google.com/search?q=https%3A%2F%2Fwww.unb.ca%2Fcic%2Fdatasets%2Fids-2017.html)
* `CICFlowMeter` (Công cụ tham khảo cách trích xuất feature): [https://github.com/ahlashkari/CICFlowMeter](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fahlashkari%2FCICFlowMeter)


* **Thực hành:** Nhúng mô hình `Isolation Forest` đã train sẵn vào Pipeline: Các gói tin/stream không vi phạm Rule sẽ được trích xuất feature và tính điểm `Anomaly Score` $\rightarrow$ Phát hiện các hành vi bất thường chưa có chữ ký.