# Scenario: WEB / COMMAND_INJECTION

| Thuộc tính | Giá trị |
|---|---|
| PCAP | `data/WEB/COMMAND_INJECTION/command_injection.pcap` |
| Scenario id | `command_injection` |
| Nhóm | WEB (khai thác web) |
| Expected rule ID | **10006** COMMAND_INJECTION |
| Severity | critical |
| Kỳ vọng alert | **CÓ** |

## Mô tả
Request HTTP chèn lệnh hệ điều hành qua tham số (`;cat /etc/passwd`). Test
Aho-Corasick đa pattern (`;cat `, `|cat `, `&&cat `, `/etc/passwd`).

## Lệnh sinh traffic (generator)
```bash
curl "http://192.168.100.30/ping.php?host=127.0.0.1;cat+/etc/passwd"
```

## Capture (IDS)
```bash
sudo ./dataset/capture_dataset.sh command_injection
# filter: tcp port 80 and host 192.168.100.30
```

## Kỳ vọng pipeline
- Normalization: `+` → space, URI chứa `;cat /etc/passwd`.
- Detection: **1 alert rule 10006**, severity critical.
- Evidence: pattern khớp (`/etc/passwd` và/hoặc `;cat `).
