# Scenario: BENIGN / DNS

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/BENIGN/DNS/dns_normal.pcap` |
| Scenario id | `benign_dns` |
| Nhóm | BENIGN (traffic bình thường) |
| Expected rule ID | — (không) |
| Severity | — |
| Kỳ vọng alert | **KHÔNG** |

## Mô tả
Vài truy vấn DNS thông thường (tên miền ngắn, ít). Dùng làm **đối chứng** cho
scenario `dns_anomaly`: cùng giao thức UDP:53 nhưng đặc trưng (độ dài, entropy,
tần suất) đều thấp nên không được khớp rule DNS tunnel.

## Lệnh sinh traffic (generator)
```bash
dig @192.168.100.30 example.com
dig @192.168.100.30 test.local
# hoặc: nslookup example.com 192.168.100.30
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh benign_dns
# filter: udp port 53 and host 192.168.100.30
```

## Kỳ vọng pipeline
- Flow: vài flow UDP :53 ngắn.
- Detection behavioral: query_length nhỏ, entropy thấp, tần suất thấp → 0 alert.
