#!/usr/bin/env bash
#
# attack_runner.sh  --  chay tren MAY GENERATOR (Kali / may sinh traffic)
#
# Sinh lan luot 13 kich ban traffic (benign + suspicious) tu generator toi
# victim-trong-lab. Dung CHUNG CAP voi capture_dataset.sh (chay tren IDS) voi
# cung ten scenario va cung thu tu, de IDS bat duoc tung luong rieng biet.
#
# CHI dung trong lab ao co lap cua ban (khong internet), voi victim la may cua
# chinh ban (192.168.100.30). Day la traffic de kiem thu rule engine phong thu
# cua ban (do true/false positive) -- giong unit test cho mot bo loc.
#
# Quy trinh moi scenario:
#   1) Tren IDS:        ./capture_dataset.sh <scenario>   (bat capture truoc)
#   2) Tren generator:  ./attack_runner.sh  <scenario>   (sinh traffic)
# Hoac chay "all" o ca hai ben cung luc.
# ---------------------------------------------------------------------------

set -u

# --- Cau hinh (sua cho khop lab) -------------------------------------------
VICTIM="${VICTIM:-192.168.100.30}"
HTTP_PORT="${HTTP_PORT:-80}"          # 80 (DVWA) hoac 3000 (Juice Shop)
SSH_USER="${SSH_USER:-user}"          # tai khoan test tren victim
STEP_DELAY="${STEP_DELAY:-3}"         # nghi giua cac scenario o che do all
WITH_SQLMAP="${WITH_SQLMAP:-0}"       # 1 = sql_evasion chay them sqlmap (nhieu alert hon)

B="\033[1m"; G="\033[32m"; Y="\033[33m"; N="\033[0m"
info()  { echo -e "${B}[*]${N} $*"; }
label() { echo -e "\n${G}================ $* ================${N}"; }
warn()  { echo -e "${Y}[!]${N} $*"; }

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<EOF
Dung: ./attack_runner.sh <scenario|all|list>

Scenario (cung ten voi capture_dataset.sh):
  benign_icmp  benign_http  benign_ssh  benign_dns
  syn_scan  port_scan  service_scan
  sql_injection  sql_evasion  command_injection  xss
  icmp_flood  dns_anomaly

Bien ghi de: VICTIM, HTTP_PORT, SSH_USER, STEP_DELAY, WITH_SQLMAP=1
Vi du:  VICTIM=192.168.100.30 ./attack_runner.sh syn_scan
EOF
}

# --- Tung scenario ----------------------------------------------------------
# BENIGN: khong nen sinh alert (dung do false positive).

s_benign_icmp() {
  label "BENIGN ICMP  (ping binh thuong)"
  ping -c 10 "$VICTIM"
}

s_benign_http() {
  label "BENIGN HTTP  (request hop le)"
  have curl || { warn "thieu curl"; return; }
  curl -s "http://${VICTIM}:${HTTP_PORT}/"            >/dev/null
  curl -s "http://${VICTIM}:${HTTP_PORT}/index.php?id=1" >/dev/null
  curl -s "http://${VICTIM}:${HTTP_PORT}/index.html"  >/dev/null
  info "Da gui 3 request HTTP hop le."
}

s_benign_ssh() {
  label "BENIGN SSH  (dang nhap binh thuong)"
  if have ssh; then
    # Phien SSH ngan, chay vai lenh roi thoat. Can nhap mat khau 1 lan.
    ssh -o StrictHostKeyChecking=no "${SSH_USER}@${VICTIM}" \
        'uname -a; whoami; ls -la; exit' || warn "SSH khong thanh cong (bo qua)."
  else
    warn "thieu ssh client."
  fi
}

s_benign_dns() {
  label "BENIGN DNS  (truy van thong thuong)"
  if have dig; then
    dig @"$VICTIM" example.com
    dig @"$VICTIM" test.local
  elif have nslookup; then
    nslookup example.com "$VICTIM"
  else
    warn "thieu dig/nslookup."
  fi
}

# RECON: ky vong behavioral alert.

s_syn_scan() {
  label "SYN SCAN  -> Rule 10002 TCP_SYN_SCAN"
  have nmap || { warn "thieu nmap"; return; }
  sudo nmap -sS "$VICTIM"
}

s_port_scan() {
  label "PORT SCAN (connect)  -> Rule 10003 PORT_SCAN"
  have nmap || { warn "thieu nmap"; return; }
  # -sT = connect() scan: bat tay day du tren cong mo roi dong ngay, khong gui
  # du lieu. Khac ky thuat voi syn_scan (-sS half-open) nen IDS phan biet duoc.
  nmap -sT -p 1-100 "$VICTIM"
}

s_service_scan() {
  label "SERVICE SCAN  -> Rule 10008 SERVICE_SCAN"
  have nmap || { warn "thieu nmap"; return; }
  nmap -sV "$VICTIM"
}

# WEB: ky vong signature/regex alert. Day la request HTTP mang payload mau de
# rule content/normalization bat duoc; victim la web app test cua chinh ban.

s_sql_injection() {
  label "SQL INJECTION  -> Rule 10004"
  have curl || { warn "thieu curl"; return; }
  curl -s -G "http://${VICTIM}:${HTTP_PORT}/index.php" \
       --data-urlencode "id=1 UNION SELECT username,password FROM users" >/dev/null
  info "Da gui payload UNION SELECT."
}

s_sql_evasion() {
  label "SQLi EVASION (comment-based)  -> Rule 10005"
  have curl || { warn "thieu curl"; return; }
  # Bien the dung inline comment de test buoc normalization xoa comment.
  curl -s "http://${VICTIM}:${HTTP_PORT}/index.php?id=1%20UNION/**/SELECT/**/1,2" >/dev/null
  # sqlmap chi chay khi WITH_SQLMAP=1: payload kiem tra WAF cua sqlmap chua ca
  # <script> va /etc/passwd nen sinh them alert 10006/10007 (khong con dung
  # ground truth "chi 10005").
  if [ "${WITH_SQLMAP:-0}" = "1" ] && have sqlmap; then
    info "Chay them sqlmap --tamper=space2comment (WITH_SQLMAP=1)..."
    sqlmap -u "http://${VICTIM}:${HTTP_PORT}/index.php?id=1" \
           --tamper=space2comment --batch --flush-session >/dev/null 2>&1 || true
  fi
  info "Da gui payload UNION/**/SELECT."
}

s_command_injection() {
  label "COMMAND INJECTION  -> Rule 10006"
  have curl || { warn "thieu curl"; return; }
  curl -s "http://${VICTIM}:${HTTP_PORT}/ping.php?host=127.0.0.1;cat+/etc/passwd" >/dev/null
  info "Da gui payload ;cat /etc/passwd."
}

s_xss() {
  label "XSS  -> Rule 10007"
  have curl || { warn "thieu curl"; return; }
  # URL-encoded <script>alert(1)</script> de test normalization URL-decode.
  curl -s "http://${VICTIM}:${HTTP_PORT}/search?q=%3Cscript%3Ealert(1)%3C/script%3E" >/dev/null
  info "Da gui payload <script>."
}

# ANOMALY: ky vong threshold/behavioral alert.

s_icmp_flood() {
  label "ICMP FLOOD  -> Rule 10009 ICMP_FLOOD"
  if have hping3; then
    info "hping3 flood ~2s roi dung..."
    sudo timeout 2 hping3 --icmp --flood "$VICTIM" || true
  else
    warn "thieu hping3, dung ping -f thay the (~2s)."
    sudo timeout 2 ping -f "$VICTIM" || true
  fi
}

s_dns_anomaly() {
  label "DNS ANOMALY (subdomain dai, entropy cao)  -> Rule 10010"
  have dig || { warn "thieu dig"; return; }
  for _ in $(seq 1 30); do
    sub=$(head -c16 /dev/urandom | xxd -p)
    dig @"$VICTIM" "${sub}.example.com" +time=1 +tries=1 >/dev/null
  done
  info "Da gui 30 truy van subdomain ngau nhien dai."
}

# --- Dieu phoi --------------------------------------------------------------
ORDER=(benign_icmp benign_http benign_ssh benign_dns \
       syn_scan port_scan service_scan \
       sql_injection sql_evasion command_injection xss \
       icmp_flood dns_anomaly)

run_one() {
  case "$1" in
    benign_icmp)       s_benign_icmp ;;
    benign_http)       s_benign_http ;;
    benign_ssh)        s_benign_ssh ;;
    benign_dns)        s_benign_dns ;;
    syn_scan)          s_syn_scan ;;
    port_scan)         s_port_scan ;;
    service_scan)      s_service_scan ;;
    sql_injection)     s_sql_injection ;;
    sql_evasion)       s_sql_evasion ;;
    command_injection) s_command_injection ;;
    xss)               s_xss ;;
    icmp_flood)        s_icmp_flood ;;
    dns_anomaly)       s_dns_anomaly ;;
    *) warn "Khong co scenario '$1'. Xem: ./attack_runner.sh list"; return 1 ;;
  esac
}

[ $# -ge 1 ] || { usage; exit 1; }

case "$1" in
  -h|--help|help) usage; exit 0 ;;
  list) printf '%s\n' "${ORDER[@]}"; exit 0 ;;
  all)
    info "Che do ALL: sinh lan luot 13 scenario toi ${VICTIM}."
    info "Dam bao IDS da chay ./capture_dataset.sh all."
    read -r -p "Nhan Enter de bat dau..." _
    for s in "${ORDER[@]}"; do
      run_one "$s"
      info "Nghi ${STEP_DELAY}s truoc scenario tiep theo..."
      sleep "$STEP_DELAY"
    done
    info "Hoan tat toan bo kich ban."
    ;;
  *) run_one "$1" ;;
esac
