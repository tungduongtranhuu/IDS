# Scenario: BENIGN / SSH

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/BENIGN/SSH/ssh_normal.pcap` |
| Scenario id | `benign_ssh` |
| Nhóm | BENIGN (traffic bình thường) |
| Expected rule ID | — (không) |
| Severity | — |
| Kỳ vọng alert | **KHÔNG** |

## Mô tả
Một phiên SSH đăng nhập bình thường, chạy vài lệnh rồi thoát. Traffic được mã
hoá nên không có payload rõ; dùng đo **false positive** và kiểm tra flow TCP
dài trên cổng 22.

## Lệnh sinh traffic (generator)
```bash
ssh user@192.168.100.30
# trong phiên: uname -a; whoami; ls -la; exit
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh benign_ssh
# filter: tcp port 22 and host 192.168.100.30
```

## Kỳ vọng pipeline
- Flow: 1 flow TCP :22, trạng thái ESTABLISHED kéo dài, kết thúc bằng FIN.
- Reassembly: stream có dữ liệu nhưng đã mã hoá (không signature nào khớp).
- Detection: 0 alert.
