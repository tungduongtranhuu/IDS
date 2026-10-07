# Scenario: ANOMALY / ICMP_FLOOD

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/ANOMALY/ICMP_FLOOD/icmp_flood.pcap` |
| Scenario id | `icmp_flood` |
| Nhóm | ANOMALY (bất thường mạng) |
| Expected rule ID | **10009** ICMP_FLOOD |
| Severity | high |
| Kỳ vọng alert | **CÓ** |

## Mô tả
Gửi ICMP với tốc độ rất cao trong thời gian ngắn (~2s). Test rule ngưỡng theo
tốc độ: đối chứng với `benign_icmp` (cùng ICMP nhưng tần suất thấp → không
alert).

## Lệnh sinh traffic (generator)
```bash
sudo hping3 --icmp --flood 192.168.100.30   # chạy ~2s rồi Ctrl+C
# không có hping3: sudo ping -f 192.168.100.30 (~2s)
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh icmp_flood
# filter: icmp and host 192.168.100.30
```

## Kỳ vọng pipeline
- Decode: rất nhiều gói ICMP từ cùng src trong <1s.
- Behavioral: ICMP packets >= 100 trong cửa sổ 1s.
- Detection: **1 alert rule 10009**, severity high.
- Lưu ý: file có thể lớn; giới hạn thời gian flood ngắn để PCAP gọn.
