# Scenario: RECON / SYN_SCAN

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/RECON/SYN_SCAN/syn_scan.pcap` |
| Scenario id | `syn_scan` |
| Nhóm | RECON (trinh sát) |
| Expected rule ID | **10002** TCP_SYN_SCAN |
| Severity | medium |
| Kỳ vọng alert | **CÓ** |

## Mô tả
Nmap SYN scan (half-open): gửi nhiều gói SYN tới nhiều cổng của victim mà
không hoàn tất bắt tay. Test khả năng đọc TCP flags + behavioral threshold.

## Lệnh sinh traffic (generator)
```bash
sudo nmap -sS 192.168.100.30
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh syn_scan
# filter: tcp and host 192.168.100.30
```

## Kỳ vọng pipeline
- Decode: nhiều gói chỉ cờ SYN từ cùng 1 src_ip tới nhiều dst_port.
- Behavioral: SYN-only flows >= 20 cổng trong cửa sổ ~5s từ cùng src.
- Detection: **1 alert rule 10002**, severity medium.
- Evidence kỳ vọng: src_ip=192.168.100.10, danh sách dst_port bị quét.
