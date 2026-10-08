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
- Feature mỗi truy vấn: subdomain = các label trừ 2 label cuối (`example.com`);
  `<32 hex>` có độ dài 32 và entropy 3.0–3.9 bit/ký tự.
- Ngưỡng (Phase 5, `rules/network.yaml`): subdomain >= 24 ký tự, entropy >= 3.0,
  và **>= 10 subdomain khác nhau của cùng domain gốc** từ cùng nguồn trong 60s.
- Ngưỡng gốc của roadmap (query_length > 50, entropy > 4.0) **không bao giờ**
  khớp traffic này: tên dài 44 ký tự, và 32 ký tự hex không thể vượt 4.0 bit
  (tối đa log2(16) = 4). Tên CDN bình thường đạt 3.5–3.8 bit, nên phải dựa vào
  sự lặp lại dưới cùng một domain chứ không phải một truy vấn đơn lẻ.
- Detection: **1 alert rule 10010**, severity high.
- Đây là rule nâng cao (không dùng Aho-Corasick) — kiểm tra ngưỡng feature.
