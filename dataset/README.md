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

Toàn bộ 12 scenario tuần tự (chạy gần như cùng lúc ở hai máy):
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
python "ids/phase 5/rule_engine.py"   data/RECON/PORT_SCAN/port_scan.pcap --mode verbose --alerts port_scan.jsonl
```

Đối chiếu **toàn bộ** dataset với bảng ground truth bên dưới (PCAP rỗng được bỏ
qua). Kết quả từng file và bảng tổng hợp nằm ở
`tests/phase 5/results/dataset/summary.txt`:

```bash
python "tests/phase 5/test_dataset.py"
```

## Lệnh sinh traffic cho từng scenario (generator)

Dưới đây là lệnh `attack_runner.sh` thực thi cho mỗi scenario. Chạy tay cũng
được — chỉ cần bật capture tương ứng trên IDS trước. Thay `192.168.100.30`
bằng IP victim của bạn nếu khác.

### BENIGN (kỳ vọng: KHÔNG alert)

```bash
# benign_icmp  — ping bình thường
ping -c 10 192.168.100.30

# benign_http  — vài request HTTP hợp lệ
curl http://192.168.100.30/
curl "http://192.168.100.30/index.php?id=1"
curl http://192.168.100.30/index.html

# benign_ssh   — phiên SSH đăng nhập, chạy vài lệnh rồi thoát
ssh user@192.168.100.30     # trong phiên: uname -a; whoami; ls -la; exit

# benign_dns   — truy vấn DNS thông thường
dig @192.168.100.30 example.com
dig @192.168.100.30 test.local
```

### RECON (kỳ vọng: behavioral alert)

```bash
# syn_scan      -> Rule 10002  (SYN half-open scan, top 1000 cổng)
sudo nmap -sS 192.168.100.30

# port_scan     -> Rule 10003  (connect scan dải cổng 1-100)
nmap -sT -p 1-100 192.168.100.30

# service_scan  -> Rule 10008  (phát hiện service/version)
nmap -sV 192.168.100.30
```

Ba scenario được phân biệt theo **kỹ thuật**, không theo số cổng (taxonomy
của Phase 5, `ids/phase 5/rules/scan.yaml`). Mỗi lần quét chỉ có **một** nhãn:

| Kỹ thuật | Dấu hiệu trên dây | Rule |
|---|---|---|
| half-open (`-sS`) | SYN tới nhiều cổng, nguồn **không bao giờ** hoàn tất bắt tay (SYN-ACK bị trả RST) | 10002 |
| connect (`-sT`) | Hoàn tất bắt tay trên cổng mở rồi đóng ngay, **không gửi dữ liệu** | 10003 |
| service (`-sV`) | Như trên, **cộng thêm** probe dữ liệu tới các service đang mở | 10008 |

> Bản trước dùng `sudo nmap -sS -p 1-100` cho `port_scan`. Lệnh đó là **cùng kỹ
> thuật** với `syn_scan`, nên trên dây hai traffic giống hệt nhau trừ số cổng, và
> không thể gán chúng cho hai rule khác nhau một cách có nguyên tắc.

### WEB (kỳ vọng: signature alert)

```bash
# sql_injection      -> Rule 10004  (UNION SELECT dạng thẳng)
curl -G "http://192.168.100.30/index.php" \
     --data-urlencode "id=1 UNION SELECT username,password FROM users"

# command_injection  -> Rule 10006  (chèn lệnh OS)
curl "http://192.168.100.30/ping.php?host=127.0.0.1;cat+/etc/passwd"

# xss                -> Rule 10007  (<script> đã URL-encode)
curl "http://192.168.100.30/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

### ANOMALY (kỳ vọng: threshold/behavioral alert)

```bash
# icmp_flood   -> Rule 10009  (ICMP tốc độ cao ~2s)
sudo hping3 --icmp --flood 192.168.100.30     # Ctrl+C sau ~2s
# không có hping3: sudo ping -f 192.168.100.30

# dns_anomaly  -> Rule 10010  (subdomain dài, entropy cao, tần suất cao)
for i in $(seq 1 30); do
  dig @192.168.100.30 "$(head -c16 /dev/urandom | xxd -p).example.com"
done
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
| 9 | command_injection | WEB/COMMAND_INJECTION/command_injection.pcap | 10006 | critical | Có |
| 10 | xss | WEB/XSS/xss.pcap | 10007 | high | Có |
| 11 | icmp_flood | ANOMALY/ICMP_FLOOD/icmp_flood.pcap | 10009 | high | Có |
| 12 | dns_anomaly | ANOMALY/DNS_ANOMALY/dns_anomaly.pcap | 10010 | high | Có |

"Alert? Có" nghĩa là **đúng một loại SID** kỳ vọng xuất hiện và không có SID
nào khác.

## Thứ tự khuyến nghị (theo `flow for build/`)

Làm 1→10 trước để chứng minh end-to-end (benign → recon → web); `icmp_flood`
và `dns_anomaly` để sau. 4 scenario BENIGN là thước đo **false positive**:
chúng phải cho 0 alert.

## Điều kiện lab

- Victim bật sẵn: SSH `:22`, HTTP `:80` (DVWA hoặc Juice Shop `:3000`), DNS resolver.
- Chỉ dùng trong mạng lab riêng, cô lập internet. Mọi IP thuộc lab của bạn.
- Công cụ generator cần có: `ping`, `curl`, `dig`/`nslookup`, `nmap`, `hping3`.
  Thiếu cái nào script báo và bỏ qua scenario đó.
