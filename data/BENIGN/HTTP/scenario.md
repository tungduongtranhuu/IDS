# Scenario: BENIGN / HTTP

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/BENIGN/HTTP/http_normal.pcap` |
| Scenario id | `benign_http` |
| Nhóm | BENIGN (traffic bình thường) |
| Expected rule ID | — (không) |
| Severity | — |
| Kỳ vọng alert | **KHÔNG** |

## Mô tả
Vài request HTTP GET hợp lệ tới web app test trên victim. Dùng đo **false
positive** cho các rule WEB (SQLi/XSS/cmd injection không được khớp nhầm với
request bình thường).

## Lệnh sinh traffic (generator)
```bash
curl http://192.168.100.30/
curl "http://192.168.100.30/index.php?id=1"
curl http://192.168.100.30/index.html
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh benign_http
# filter: tcp port 80 and host 192.168.100.30
```

## Kỳ vọng pipeline
- Flow: mỗi request là 1 flow TCP :80, bắt tay SYN→...→FIN đầy đủ.
- Reassembly: dựng lại được HTTP request line + headers.
- Normalization: URI sạch, không chứa pattern tấn công.
- Detection: 0 alert.
