"""Phase 3 constants: TCP flags, TCP states, flow status and end reasons."""

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80
TCP_FLAG_NAMES = (
    (TCP_SYN, "SYN"),
    (TCP_FIN, "FIN"),
    (TCP_RST, "RST"),
    (TCP_PSH, "PSH"),
    (TCP_ACK, "ACK"),
    (TCP_URG, "URG"),
    (TCP_ECE, "ECE"),
    (TCP_CWR, "CWR"),
)

# Lifecycle states of a TCP flow (both directions combined).
TCP_NONE = "NONE"
TCP_SYN_SENT = "SYN_SENT"
TCP_SYN_RECEIVED = "SYN_RECEIVED"
TCP_ESTABLISHED = "ESTABLISHED"
TCP_MIDSTREAM = "MIDSTREAM"
TCP_FIN_WAIT = "FIN_WAIT"
TCP_CLOSING = "CLOSING"
TCP_CLOSED = "CLOSED"

# ICMP reply types: the sender of a reply is the server side.
ICMP_REPLY_TYPES = {0, 14, 16, 18}

# Flow status and termination reasons.
STATUS_ACTIVE = "ACTIVE"
STATUS_EXPIRED = "EXPIRED"
STATUS_CLOSED = "CLOSED"
END_TIMEOUT = "TIMEOUT"
END_ACTIVE_TIMEOUT = "ACTIVE_TIMEOUT"
END_TCP_RST = "TCP_RST"
END_TCP_FIN = "TCP_FIN"
END_TCP_PORT_REUSE = "TCP_PORT_REUSE"
END_OF_CAPTURE = "END_OF_CAPTURE"
