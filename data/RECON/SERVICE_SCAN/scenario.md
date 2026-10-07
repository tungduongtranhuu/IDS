# Scenario: RECON / SERVICE_SCAN

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/RECON/SERVICE_SCAN/service_scan.pcap` |
| Scenario id | `service_scan` |
| Nhóm | RECON (trinh sát) |
| Expected rule ID | **10008** SERVICE_SCAN |
| Severity | medium |
| Kỳ vọng alert | **CÓ** |

## Mô tả
Nmap service/version detection (`-sV`): hoàn tất bắt tay rồi gửi probe để lấy
banner dịch vụ. Khác SYN scan ở chỗ có connection đầy đủ + payload probe. Dùng
để tinh chỉnh behavioral và phân biệt với SYN/PORT scan.

## Lệnh sinh traffic (generator)
```bash
nmap -sV 192.168.100.30
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh service_scan
# filter: host 192.168.100.30
```

## Kỳ vọng pipeline
- Flow: nhiều flow TCP ESTABLISHED tới các cổng mở, có trao đổi payload probe.
- Behavioral: unique_dst_ports >= 10 trong ~3s (có bắt tay hoàn chỉnh).
- Detection: **1 alert rule 10008**, severity medium.
- Lưu ý: có thể trùng tín hiệu với 10002/10003 — kiểm tra taxonomy để không
  đếm trùng một hành vi thành nhiều alert khác loại.
