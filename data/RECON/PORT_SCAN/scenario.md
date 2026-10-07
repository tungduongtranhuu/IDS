# Scenario: RECON / PORT_SCAN

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/RECON/PORT_SCAN/port_scan.pcap` |
| Scenario id | `port_scan` |
| Nhóm | RECON (trinh sát) |
| Expected rule ID | **10003** PORT_SCAN |
| Severity | high |
| Kỳ vọng alert | **CÓ** |

## Mô tả
Quét một dải cổng (1–100) của victim. Test state tracking theo src_ip và
ngưỡng `unique_dst_ports` trong cửa sổ thời gian.

## Lệnh sinh traffic (generator)
```bash
sudo nmap -sS -p 1-100 192.168.100.30
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh port_scan
# filter: tcp and host 192.168.100.30
```

## Kỳ vọng pipeline
- Flow: 1 src_ip → nhiều dst_port riêng biệt.
- Behavioral: unique_dst_ports >= 30 trong time_window ~5s.
- Detection: **1 alert rule 10003**, severity high.
- Evidence: source_ip=192.168.100.10, destination_ip=192.168.100.30, số cổng.
