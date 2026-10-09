#!/usr/bin/env bash
#
# capture_dataset.sh  --  chay tren MAY IDS (Ubuntu, o giua)
#
# Bat tcpdump voi BPF filter rieng cho tung scenario, luu file dung duong dan
# data/<CATEGORY>/<NAME>/<name>.pcap. Moi scenario capture trong mot cua so
# thoi gian co dinh (timeout) roi tu dung, nen co the chay tung cai hoac "all".
#
# Dung chung cap voi attack_runner.sh (chay tren may generator). Quy trinh:
#   1) Tren IDS:        ./capture_dataset.sh <scenario>   (hoac: all)
#   2) Ngay sau do tren generator: ./attack_runner.sh <scenario>  (hoac: all)
# Hai ben dung cung ten scenario va cung thu tu. Cua so capture dai hon thoi
# gian sinh traffic nen khong can bam gio chinh xac tung giay.
#
# Lab co lap: generator=192.168.100.10, victim=192.168.100.30, IDS nghe o giua.
# ---------------------------------------------------------------------------

set -u

# --- Cau hinh (sua cho khop lab cua ban) ----------------------------------
IFACE="${IFACE:-enp0s3}"          # interface IDS dang nghe (ip link de xem)
VICTIM="${VICTIM:-192.168.100.30}"
GENERATOR="${GENERATOR:-192.168.100.10}"
# Thu muc goc repo = thu muc cha cua script nay
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="${ROOT}/data"

# --- Bang scenario ----------------------------------------------------------
# Moi dong: ten|category|name|duong_dan_pcap|BPF_filter|so_giay_capture
# BPF filter giu file sach (chi traffic giua generator<->victim lien quan).
SCENARIOS=(
  "benign_icmp|BENIGN|ICMP|BENIGN/ICMP/icmp_normal.pcap|icmp and host ${VICTIM}|15"
  "benign_http|BENIGN|HTTP|BENIGN/HTTP/http_normal.pcap|tcp port 80 and host ${VICTIM}|20"
  "benign_ssh|BENIGN|SSH|BENIGN/SSH/ssh_normal.pcap|tcp port 22 and host ${VICTIM}|25"
  "benign_dns|BENIGN|DNS|BENIGN/DNS/dns_normal.pcap|udp port 53 and host ${VICTIM}|15"
  "syn_scan|RECON|SYN_SCAN|RECON/SYN_SCAN/syn_scan.pcap|tcp and host ${VICTIM}|30"
  "port_scan|RECON|PORT_SCAN|RECON/PORT_SCAN/port_scan.pcap|tcp and host ${VICTIM}|30"
  "service_scan|RECON|SERVICE_SCAN|RECON/SERVICE_SCAN/service_scan.pcap|host ${VICTIM}|40"
  "sql_injection|WEB|SQL_INJECTION|WEB/SQL_INJECTION/sql_injection.pcap|tcp port 80 and host ${VICTIM}|20"
  "command_injection|WEB|COMMAND_INJECTION|WEB/COMMAND_INJECTION/command_injection.pcap|tcp port 80 and host ${VICTIM}|20"
  "xss|WEB|XSS|WEB/XSS/xss.pcap|tcp port 80 and host ${VICTIM}|20"
  "icmp_flood|ANOMALY|ICMP_FLOOD|ANOMALY/ICMP_FLOOD/icmp_flood.pcap|icmp and host ${VICTIM}|15"
  "dns_anomaly|ANOMALY|DNS_ANOMALY|ANOMALY/DNS_ANOMALY/dns_anomaly.pcap|udp port 53 and host ${VICTIM}|20"
)

# --- Tien ich ---------------------------------------------------------------
die()  { echo "[!] $*" >&2; exit 1; }
info() { echo "[*] $*"; }

usage() {
  cat <<EOF
Dung: sudo ./capture_dataset.sh <scenario|all|list>

  list                     Liet ke tat ca scenario
  all                      Capture lan luot ca 12 scenario (tung cua so timeout)
  <ten_scenario>           Capture dung 1 scenario

Bien moi truong ghi de duoc: IFACE, VICTIM, GENERATOR
Vi du:  sudo IFACE=eth0 ./capture_dataset.sh syn_scan
EOF
}

find_row() {
  local want="$1"
  for row in "${SCENARIOS[@]}"; do
    [ "${row%%|*}" = "$want" ] && { echo "$row"; return 0; }
  done
  return 1
}

capture_one() {
  local row="$1"
  IFS='|' read -r name cat sub relpath bpf secs <<< "$row"
  local out="${DATA}/${relpath}"
  mkdir -p "$(dirname "$out")"
  rm -f "$out"

  echo
  info "=============================================================="
  info " Scenario : ${name}   (${cat}/${sub})"
  info " Luu vao  : ${out}"
  info " Filter   : ${bpf}"
  info " Cua so   : ${secs}s  --  HAY chay attack tuong ung tren generator NGAY BAY GIO"
  info "=============================================================="

  # -w ghi pcap, timeout tu dung sau <secs>, giu file du attack chua xong.
  # stdbuf de ban thay dong packet count neu muon doi -q.
  timeout "${secs}" tcpdump -i "$IFACE" -w "$out" -n $bpf
  local rc=$?
  # timeout tra 124 khi het gio (binh thuong voi cach bat theo cua so).
  if [ $rc -ne 0 ] && [ $rc -ne 124 ] && [ $rc -ne 143 ]; then
    die "tcpdump loi (rc=$rc). Kiem tra IFACE='${IFACE}' va quyen root."
  fi

  if [ -s "$out" ]; then
    local n
    n=$(tcpdump -r "$out" 2>/dev/null | wc -l)
    info "Xong: ${out}  (${n} packet)"
  else
    echo "[!] CANH BAO: ${out} rong. Co the attack chua chay, sai IFACE, hoac filter khong khop." >&2
  fi
}

# --- Main -------------------------------------------------------------------
[ $# -ge 1 ] || { usage; exit 1; }

case "$1" in
  -h|--help|help) usage; exit 0 ;;
  list)
    printf "%-20s %-10s %-16s %s\n" "SCENARIO" "CATEGORY" "SUBDIR" "PCAP"
    for row in "${SCENARIOS[@]}"; do
      IFS='|' read -r name cat sub relpath bpf secs <<< "$row"
      printf "%-20s %-10s %-16s %s\n" "$name" "$cat" "$sub" "$relpath"
    done
    exit 0 ;;
esac

[ "$(id -u)" -eq 0 ] || die "Can chay bang root (sudo) de bat goi."
command -v tcpdump >/dev/null || die "Chua cai tcpdump:  sudo apt install tcpdump"

info "IDS interface=${IFACE}  victim=${VICTIM}  generator=${GENERATOR}"
info "Data root: ${DATA}"

if [ "$1" = "all" ]; then
  info "Che do ALL: se chay lan luot 12 scenario."
  info "Ben generator hay chay:  ./attack_runner.sh all   (bat dau cung luc)."
  read -r -p "Nhan Enter de bat dau..." _
  for row in "${SCENARIOS[@]}"; do
    capture_one "$row"
  done
  info "Hoan tat toan bo dataset."
else
  row="$(find_row "$1")" || die "Khong co scenario '$1'. Xem: ./capture_dataset.sh list"
  capture_one "$row"
fi
