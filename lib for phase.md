# 3. Bây giờ cài `dpkt`

Sau khi nhìn thấy:

```text
(venv) ubuntu@IDSubuntu:~/ids-project$
```

chạy:

```bash
python -m pip install dpkt
```

Sau đó kiểm tra:

```bash
python -c "import dpkt; print(dpkt.__version__)"
```

và:

```bash
python -c "import dpkt; print(dpkt.__file__)"
```

Bạn sẽ thấy đường dẫn kiểu:

```text
/home/ubuntu/ids-project/venv/lib/python3.14/site-packages/dpkt/...
```

Như vậy là OK.

---

# 4. Nếu `venv` của bạn chưa hoàn chỉnh

Nếu chạy:

```bash
source venv/bin/activate
```

mà vẫn lỗi, kiểm tra:

```bash
ls -la venv
```

và:

```bash
ls -la venv/bin
```

Bạn phải thấy các file kiểu:

```text
activate
python
pip
```

Nếu không có, tạo lại `venv`.

Bạn **không cần sợ tạo lại nếu đây mới là lúc setup project**:

```bash
rm -rf venv
python3 -m venv venv
```

Sau đó:

```bash
source venv/bin/activate
```

rồi:

```bash
python -m pip install --upgrade pip
python -m pip install dpkt
```

---

# 5. Còn project IDS của bạn cần những thư viện nào?

Đây là điểm mình muốn chỉnh lại so với roadmap ban đầu.

**Không nên cài tất cả ngay bây giờ.**

Project của bạn có nhiều Phase, nên dependency nên được cài **theo Phase**.

## Phase 2 — Packet Capture + Decode

Hiện tại bạn chỉ cần:

```text
Python Standard Library
├── socket
├── struct
├── argparse
├── time
├── datetime
└── os

External:
└── dpkt
```

Vì vậy:

```bash
python -m pip install dpkt
```

**là đủ cho Phase 2.**

Bạn không cần cài:

```text
❌ scapy
❌ pyahocorasick
❌ scikit-learn
❌ joblib
❌ PyYAML
```

ngay lúc này.

---

# 6. Sau này dependency của project sẽ như thế nào?

Mình khuyên project của bạn chia như sau:

### Phase 2 — Capture

```text
dpkt
```

---

### Phase 3 — Anti-Evasion / Reassembly

Phần lớn vẫn dùng Python standard library:

```text
collections
dataclasses
heapq
bisect
time
ipaddress
urllib.parse
```

→ **Không cần pip thêm nhiều.**

---

### Phase 4 — Rule Engine

Bạn cần:

```text
PyYAML
```

nếu rule dùng YAML.

và:

```text
pyahocorasick
```

cho Aho-Corasick.

Cài lúc đến Phase 4:

```bash
python -m pip install PyYAML pyahocorasick
```

---

### Phase 5 — Multiprocessing

Python có sẵn:

```text
multiprocessing
queue
shared_memory
logging
json
```

→ **Không cần pip.**

---

### Phase 6 — Machine Learning

Lúc đó mới cài:

```text
scikit-learn
joblib
numpy
pandas
```

Ví dụ:

```bash
python -m pip install scikit-learn joblib pandas
```

`numpy` sẽ thường được kéo vào như dependency.

---

# 7. Dependency cuối cùng có thể thành

Khi project hoàn thiện:

```text
ids-project/
│
├── venv/
│
├── phase2_capture.py
├── phase2_decode.py
│
├── reassembly/
│
├── rules/
│
├── detection/
│
├── ml/
│
├── logs/
│
├── tests/
│
└── requirements.txt
```

`requirements.txt` có thể cuối cùng chứa:

```text
dpkt
PyYAML
pyahocorasick
numpy
pandas
scikit-learn
joblib
```

Nhưng **bây giờ chưa cần cài toàn bộ**.

---

# 8. Làm ngay theo đúng thứ tự này

Bạn đang ở:

```text
ubuntu@IDSubuntu:~/ids-project$
```

Hãy copy từng lệnh sau:

```bash
cd ~/ids-project
```

### Bước 1 — Kiểm tra venv

```bash
ls -la
```

Bạn đang có:

```text
venv
```

### Bước 2 — Activate

```bash
source venv/bin/activate
```

Terminal phải thành:

```text
(venv) ubuntu@IDSubuntu:~/ids-project$
```

### Bước 3 — Kiểm tra Python

```bash
which python
```

Kết quả phải là:

```text
/home/ubuntu/ids-project/venv/bin/python
```

### Bước 4 — Kiểm tra pip

```bash
python -m pip --version
```

Nó phải trỏ vào:

```text
/home/ubuntu/ids-project/venv/...
```

### Bước 5 — Cài dpkt

```bash
python -m pip install dpkt
```

### Bước 6 — Test

```bash
python -c "import dpkt; print('dpkt OK:', dpkt.__version__)"
```

### Bước 7 — Xem toàn bộ package

```bash
python -m pip list
```

---

## 9. Một nguyên tắc bạn nên nhớ từ giờ

Bạn có thể coi:

```text
python3
```

là **Python của Ubuntu**.

Còn sau:

```bash
source venv/bin/activate
```

thì:

```text
python
```

là **Python của project IDS**.

Vì vậy trong project, mình khuyên bạn luôn dùng:

```bash
python -m pip install ...
```

thay vì:

```bash
pip install ...
```

Nó giúp tránh nhầm `pip` của system với `pip` của `venv`.

---

### Và một điểm cuối rất quan trọng

**Bạn không cần tạo `venv` lại mỗi lần mở Ubuntu.**

Project của bạn đang là:

```text
~/ids-project/
│
├── venv/        ← đã tạo, giữ nguyên
│
└── code IDS
```

Mỗi lần mở Ubuntu:

```bash
cd ~/ids-project
source venv/bin/activate
```

là đủ.

Các thư viện đã cài trong:

```text
~/ids-project/venv/
```

**không bị xóa khi bạn shutdown/restart Ubuntu.**

Nếu sau khi chạy `source venv/bin/activate` mà `which python` vẫn không trỏ vào `~/ids-project/venv/bin/python`, gửi mình output của **3 lệnh** này:

```bash
ls -la
which python
python -m pip --version
```

mình sẽ xác định chính xác environment của bạn đang bị vướng ở đâu.
