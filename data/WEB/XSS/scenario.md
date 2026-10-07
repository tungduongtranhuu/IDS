# Scenario: WEB / XSS

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/WEB/XSS/xss.pcap` |
| Scenario id | `xss` |
| Nhóm | WEB (khai thác web) |
| Expected rule ID | **10007** XSS_SCRIPT_TAG |
| Severity | high |
| Kỳ vọng alert | **CÓ** |

## Mô tả
Request HTTP với payload `<script>alert(1)</script>` đã URL-encode. Test
normalization URL-decode trước khi khớp signature `<script`.

## Lệnh sinh traffic (generator)
```bash
curl "http://192.168.100.30/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh xss
# filter: tcp port 80 and host 192.168.100.30
```

## Kỳ vọng pipeline
- Payload thô chứa `%3Cscript%3E` → rule thẳng không khớp.
- Normalization URL-decode → `<script>`.
- Detection: **1 alert rule 10007**, severity high.
