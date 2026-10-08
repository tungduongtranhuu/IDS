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
- Behavioral: scan episode có technique `service` (nguồn gửi dữ liệu sau bắt
  tay), >= 10 cổng trong 5s. Episode chỉ đóng sau 10s im lặng, nên phần quét
  cổng và phần probe (cách nhau vài giây) nằm trong cùng một episode.
- Detection: **1 alert rule 10008**, severity medium. Mỗi episode chỉ mang một
  nhãn kỹ thuật, nên không có thêm 10002/10003 cho cùng lần quét.
- Lưu ý: nếu victim chỉ mở dịch vụ tự gửi banner (vd chỉ SSH), nmap không gửi
  probe nào và episode sẽ được xếp `connect` (10003). Victim lab có HTTP nên ổn.
