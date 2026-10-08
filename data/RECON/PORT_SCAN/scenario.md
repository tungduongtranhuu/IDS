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
Connect scan (`-sT`) một dải cổng (1–100) của victim: trên cổng mở, nmap hoàn
tất bắt tay rồi đóng ngay, không gửi dữ liệu. Test state tracking theo cặp
(src, dst) và ngưỡng `unique_dst_ports` trong cửa sổ thời gian. Khác
`syn_scan` ở **kỹ thuật** (bắt tay hoàn tất), không chỉ ở số cổng.

## Lệnh sinh traffic (generator)
```bash
nmap -sT -p 1-100 192.168.100.30     # không cần sudo
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh port_scan
# filter: tcp and host 192.168.100.30
```

## Kỳ vọng pipeline
- Flow: 1 src_ip → 100 dst_port; cổng mở có `handshake_completed`, cổng đóng trả RST.
- Behavioral: scan episode có technique `connect`, >= 30 cổng trong 5s.
- Detection: **1 alert rule 10003**, severity high (không có 10002 hay 10008).
- Evidence: source_ip=192.168.100.10, destination_ip=192.168.100.30,
  `ports_probed=100`, `handshakes_completed` = số cổng mở.
