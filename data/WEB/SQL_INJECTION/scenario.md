# Scenario: WEB / SQL_INJECTION

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/WEB/SQL_INJECTION/sql_injection.pcap` |
| Scenario id | `sql_injection` |
| Nhóm | WEB (khai thác web) |
| Expected rule ID | **10004** SQL_INJECTION_UNION |
| Severity | high |
| Kỳ vọng alert | **CÓ** |

## Mô tả
Request HTTP mang payload `UNION SELECT` dạng "đẹp" (không obfuscate) tới web
app test. Đây là bản đối chứng cho `sql_evasion`: chứng minh signature khớp
payload thẳng. Test signature detection (Aho-Corasick) trên buffer `http_uri`.

## Lệnh sinh traffic (generator)
```bash
curl -G "http://192.168.100.30/index.php" \
     --data-urlencode "id=1 UNION SELECT username,password FROM users"
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh sql_injection
# filter: tcp port 80 and host 192.168.100.30
```

## Kỳ vọng pipeline
- Reassembly: dựng lại HTTP request line đầy đủ.
- Normalization: URL-decode → URI chứa chuỗi `union select`.
- Detection: **1 alert rule 10004**, severity high.
- Evidence: raw payload + normalized payload chứa `union select`.
