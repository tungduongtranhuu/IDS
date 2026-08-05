Network Interface
       │
       ▼
phase2_capture.py
       │
       │ raw packet
       ▼
capture.pcap
       │
       ▼
phase2_decode.py
       │
       ├── Ethernet
       ├── IPv4
       ├── TCP
       ├── UDP
       └── 5-tuple