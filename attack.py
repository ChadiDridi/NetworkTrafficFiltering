#!/usr/bin/env python3
from scapy.all import IP, ICMP, send

TARGET_IP = "127.0.0.1"
# Send 100 ICMP packets
for i in range(100):
    pkt = IP(dst=TARGET_IP)/ICMP()
    print("→ Sending ICMP packet", i, pkt.summary())
    send(pkt, iface="lo", verbose=False)
