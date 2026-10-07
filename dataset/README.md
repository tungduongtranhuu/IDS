# Dataset capture toolkit

Bộ công cụ sinh dataset PCAP **thật** cho IDS, thu trong lab ảo cô lập
(generator `192.168.100.10` → victim-trong-lab `192.168.100.30`, IDS nghe ở
giữa). Thay cho việc dựng gói tổng hợp như `tests/phase 4/pcap_factory.py`:
ở đây traffic là thật, đi qua interface và được IDS bắt lại — đúng tinh thần
"Kali là traffic generator, IDS quan sát" trong `flow for build/`.

## Hai script

| Script | Chạy trên | Vai trò |
|---|---|---|
| `capture_dataset.sh` | máy IDS (Ubuntu) | bật `tcpdump` + BPF filter, lưu đúng `data/<CAT>/<NAME>/<name>.pcap` |
| `attack_runner.sh` | máy generator (Kali) | sinh traffic cho từng scenario, có nhãn + delay |

Cả hai dùng **cùng tên scenario** và **cùng thứ tự**.

## Cách dùng

Một scenario (khuyên dùng khi mới bắt đầu — dễ kiểm soát):
```bash
# Trên IDS (bật trước, tự dừng sau cửa sổ timeout):
sudo ./dataset/capture_dataset.sh syn_scan
# Trên generator (chạy ngay sau đó):
./dataset/attack_runner.sh syn_scan
```

Toàn bộ 13 scenario tuần tự (chạy gần như cùng lúc ở hai máy):
```bash
sudo ./dataset/capture_dataset.sh all     # trên IDS
./dataset/attack_runner.sh all            # trên generator
```

Tiện ích: `./...sh list` liệt kê scenario. Ghi đè cấu hình bằng biến môi
trường: `IFACE`, `VICTIM`, `GENERATOR`, `HTTP_PORT`, `SSH_USER`, `STEP_DELAY`.
```bash
sudo IFACE=eth0 VICTIM=192.168.100.30 ./dataset/capture_dataset.sh all
```

## Kiểm tra lại PCAP bằng chính engine

```bash
python "ids/phase 2/packet_decode.py" data/RECON/PORT_SCAN/port_scan.pcap --mode verbose
python "ids/phase 3/flow_manager.py"  data/RECON/PORT_SCAN/port_scan.pcap --mode verbose
python "ids/phase 4/anti_evasion.py"  data/RECON/PORT_SCAN/port_scan.pcap --mode verbose
```

## Ground truth (tổng hợp)

Chi tiết từng scenario xem file `scenario.md` trong thư mục data tương ứng.

| # | Scenario | PCAP | Rule | Severity | Alert? |
|---|---|---|---|---|---|
| 1 | benign_icmp | BENIGN/ICMP/icmp_normal.pcap | — | — | Không |
| 2 | benign_http | BENIGN/HTTP/http_normal.pcap | — | — | Không |
| 3 | benign_ssh | BENIGN/SSH/ssh_normal.pcap | — | — | Không |
| 4 | benign_dns | BENIGN/DNS/dns_normal.pcap | — | — | Không |
| 5 | syn_scan | RECON/SYN_SCAN/syn_scan.pcap | 10002 | medium | Có |
| 6 | port_scan | RECON/PORT_SCAN/port_scan.pcap | 10003 | high | Có |
| 7 | service_scan | RECON/SERVICE_SCAN/service_scan.pcap | 10008 | medium | Có |
| 8 | sql_injection | WEB/SQL_INJECTION/sql_injection.pcap | 10004 | high | Có |
| 9 | sql_evasion | WEB/SQL_EVASION/sql_comment_evasion.pcap | 10005 | high | Có |
| 10 | command_injection | WEB/COMMAND_INJECTION/command_injection.pcap | 10006 | critical | Có |
| 11 | xss | WEB/XSS/xss.pcap | 10007 | high | Có |
| 12 | icmp_flood | ANOMALY/ICMP_FLOOD/icmp_flood.pcap | 10009 | high | Có |
| 13 | dns_anomaly | ANOMALY/DNS_ANOMALY/dns_anomaly.pcap | 10010 | high | Có |

## Thứ tự khuyến nghị (theo `flow for build/`)

Làm 1→9 trước để chứng minh end-to-end (benign → recon → web); `icmp_flood`
và `dns_anomaly` để sau. 4 scenario BENIGN là thước đo **false positive**:
chúng phải cho 0 alert.

## Điều kiện lab

- Victim bật sẵn: SSH `:22`, HTTP `:80` (DVWA hoặc Juice Shop `:3000`), DNS resolver.
- Chỉ dùng trong mạng lab riêng, cô lập internet. Mọi IP thuộc lab của bạn.
- Công cụ generator cần có: `ping`, `curl`, `dig`/`nslookup`, `nmap`, `hping3`,
  (tuỳ chọn) `sqlmap`. Thiếu cái nào script báo và bỏ qua scenario đó.
