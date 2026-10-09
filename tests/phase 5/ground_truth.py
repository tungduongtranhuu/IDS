"""Expected detection result of every dataset scenario (dataset/README.md table).

None = BENIGN: the capture must produce zero alerts (false positive check).
"""

GROUND_TRUTH = {
    # scenario:          (PCAP under data/,                              expected SID)
    "benign_icmp":       ("BENIGN/ICMP/icmp_normal.pcap",                None),
    "benign_http":       ("BENIGN/HTTP/http_normal.pcap",                None),
    "benign_ssh":        ("BENIGN/SSH/ssh_normal.pcap",                  None),
    "benign_dns":        ("BENIGN/DNS/dns_normal.pcap",                  None),
    "syn_scan":          ("RECON/SYN_SCAN/syn_scan.pcap",                10002),
    "port_scan":         ("RECON/PORT_SCAN/port_scan.pcap",              10003),
    "service_scan":      ("RECON/SERVICE_SCAN/service_scan.pcap",        10008),
    "sql_injection":     ("WEB/SQL_INJECTION/sql_injection.pcap",        10004),
    "command_injection": ("WEB/COMMAND_INJECTION/command_injection.pcap", 10006),
    "xss":               ("WEB/XSS/xss.pcap",                            10007),
    "icmp_flood":        ("ANOMALY/ICMP_FLOOD/icmp_flood.pcap",          10009),
    "dns_anomaly":       ("ANOMALY/DNS_ANOMALY/dns_anomaly.pcap",        10010),
}

PCAP_GLOBAL_HEADER_BYTES = 24


def expected_sids(scenario: str) -> set[int]:
    sid = GROUND_TRUTH[scenario][1]
    return set() if sid is None else {sid}
