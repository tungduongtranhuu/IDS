# Scenario: BENIGN / ICMP

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/BENIGN/ICMP/icmp_normal.pcap` |
| Scenario id | `benign_icmp` |
| Nhóm | BENIGN (traffic bình thường) |
| Expected rule ID | — (không) |
| Severity | — |
| Kỳ vọng alert | **KHÔNG** |

## Mô tả
Ping ICMP echo bình thường từ generator tới victim trong lab. Dùng để đo
**false positive**: pipeline phải xử lý ICMP hợp lệ mà không sinh cảnh báo.

## Lệnh sinh traffic (generator)
```bash
ping -c 10 192.168.100.30
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh benign_icmp
# filter: icmp and host 192.168.100.30
```

## Kỳ vọng pipeline
- Decode: ~20 gói ICMP (10 request + 10 reply), `ip_protocol=ICMP`, `icmp_type` 8/0.
- Flow: 1 flow ICMP hai chiều.
- Detection: không rule nào khớp → 0 alert.
