Sniffers and spoofers written in Python and C.

# Table Of Contents:

- [Requirements](#requirements)
- [Available Programs](#available-programs)
- [How to run programs](#running-programs)

# Requirements

- Python: **scapy**
- C: **libpcap**

**Installation:**

```bash

# To install scapy:

$ pip install scapy

# To install libpcap on ubuntu:

$ sudo apt install libpcap-dev
```

# Available Programs

- Python:

  - **ping_spoofer.py** : Ping spoofer written using scapy
  - **traceroute.py** : Traceroute program using ICMP message for exceeding TTL
  - sniff_icmp_tcp.py : Structure of simple sniffer program using scapy

- C:

  - **ping_spoofer.c** : Ping spoofer written using libpcap and raw sockets
  - sniff_icmp_tcp.c : Sniffer that only parses ICMP and TCP packets
  - spoof_icmp_echo_request.c : Simple icmp echo requests spoofer using raw sockets
  - spoof_src_ip.c : Simple ip source address spoofer using raw sockets

# Running Programs

- Python:

```bash
$ python ./program_name.py
```

- C:

```bash
$ gcc program_name.c -o program_name -lpcap
$ ./program_name
```
