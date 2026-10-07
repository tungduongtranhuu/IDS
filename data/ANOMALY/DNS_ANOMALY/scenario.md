# Scenario: ANOMALY / DNS_ANOMALY

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/ANOMALY/DNS_ANOMALY/dns_anomaly.pcap` |
| Scenario id | `dns_anomaly` |
| Nhóm | ANOMALY (bất thường mạng) |
| Expected rule ID | **10010** POSSIBLE_DNS_TUNNEL |
| Severity | high |
| Kỳ vọng alert | **CÓ** |

## Mô tả
Nhiều truy vấn DNS với subdomain dài, ngẫu nhiên (entropy cao), tần suất cao —
mô phỏng dấu hiệu DNS tunneling. Đối chứng với `benign_dns`. Test behavioral
detection dựa trên feature (query_length, entropy, queries_per_second).

## Lệnh sinh traffic (generator)
```bash
for i in $(seq 1 30); do
  dig @192.168.100.30 "$(head -c16 /dev/urandom | xxd -p).example.com"
done
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh dns_anomaly
# filter: udp port 53 and host 192.168.100.30
```

## Kỳ vọng pipeline
- Feature: query_length > 50, entropy > 4.0, queries_per_second cao.
- Detection: **1 alert rule 10010**, severity high.
- Đây là rule nâng cao (không dùng Aho-Corasick) — kiểm tra ngưỡng feature.
