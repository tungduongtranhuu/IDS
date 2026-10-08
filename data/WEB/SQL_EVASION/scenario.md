# Scenario: WEB / SQL_EVASION

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/WEB/SQL_EVASION/sql_comment_evasion.pcap` |
| Scenario id | `sql_evasion` |
| Nhóm | WEB (khai thác web) |
| Expected rule ID | **10005** SQL_COMMENT_EVASION |
| Severity | high |
| Kỳ vọng alert | **CÓ** |

## Mô tả
Cùng ý đồ SQLi nhưng dùng inline comment (`UNION/**/SELECT`) để né signature
thẳng. Đây là cặp "2 PCAP cho cùng 1 attack" với `sql_injection` — chứng minh
**anti-evasion**: chỉ sau bước normalization (xoá comment) mới khớp.

## Lệnh sinh traffic (generator)
```bash
curl "http://192.168.100.30/index.php?id=1%20UNION/**/SELECT/**/1,2"
# tuỳ chọn (WITH_SQLMAP=1, sinh thêm nhiều alert khác):
# sqlmap -u "http://192.168.100.30/index.php?id=1" --tamper=space2comment --batch
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh sql_evasion
# filter: tcp port 80 and host 192.168.100.30
```

## Kỳ vọng pipeline
- Rule signature thẳng (`union select`) **KHÔNG** khớp trên payload thô.
- Normalization: xoá/chuẩn hoá comment → `union select` (buffer `http_uri`).
- Regex 10005 chạy trên `http_uri_decoded` (còn giữ comment) → khớp `UNION/**/SELECT`.
- Detection: **1 alert rule 10005** (regex), severity high. 10004 cũng khớp
  bản chuẩn hoá nhưng bị 10005 `supersedes` trên cùng request
  (evidence `superseded_sids: [10004]`).
- Đây là điểm minh hoạ đắt giá cho anti-evasion trong báo cáo/CV.
