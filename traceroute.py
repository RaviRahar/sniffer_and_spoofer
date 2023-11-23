#!/usr/bin/env python3
import sys
from scapy.all import *

# Taking first argument to script as final destination IP
if len(sys.argv) > 1:
    ip_final_dst = sys.argv[1]
else:
    print("ERROR: Supply IP Address as argument")
    exit()

a=IP()
a.dst = ip_final_dst

# Boolean that checks if packet received is from final destination
dst_reached = True
# function to print IPs of Route Points
# Also sets dst_reached to True when packet received is from final destination
def print_pkt(pkt):
    ip_src = pkt.sprintf("{IP:%IP.src%}")
    global ip_final_dst, dst_reached
    if (ip_final_dst == ip_src):
        print("Destination Reached")
        dst_reached = False
        return
    print(f"Route Point: {ip_src}")

# using AsyncSniffer to sniff in parallel
sniffer = AsyncSniffer(iface=["enp0s3"], store=False, filter=f"icmp and not dst host {ip_final_dst}", prn=print_pkt)
sniffer.start()
print("Tracing Route ...")

# Sending packets with increaing ttl by 1 each time
# Stops when dst_reached is True
a.ttl = 1
while(dst_reached):
    send(a / ICMP(), verbose=False)
    a.ttl += 1
    time.sleep(0.5)
# Stopping sniffer
sniffer.stop()
