#!/usr/bin/env python3
from scapy.all import Ether, IP, ICMP, sendp
import time, statistics

# === Configuration ===
TARGET_IP = "10.0.2.30"          # destination IP (h3)
SRC_MAC   = "08:00:00:00:01:11"  # h1 MAC
DST_MAC   = "08:00:00:00:03:33"  # h3 MAC
IFACE     = "eth0"               # inside h1 namespace
COUNT     = 100
PAYLOAD_SIZE = 10000   # bytes per packet
INTERVAL  = 0.001                # seconds between sends
# ======================

payload = b"A" * PAYLOAD_SIZE
rtts = []

print(f"Sending {COUNT} ICMP packets ({PAYLOAD_SIZE} B) with interval {INTERVAL} to {TARGET_IP} ...")

start = time.time()
for i in range(COUNT):
    pkt = Ether(src=SRC_MAC, dst=DST_MAC)/IP(dst=TARGET_IP)/ICMP(seq=i)/payload
    sendp(pkt, iface=IFACE, verbose=0)
    time.sleep(INTERVAL)
end = time.time()

duration = end - start
throughput_bps  = (COUNT * (PAYLOAD_SIZE + 14 + 20 + 8) * 8) / duration  # Ethernet + IP + ICMP hdrs
throughput_mbps = throughput_bps / 1e6

print("\n=== ICMP Throughput ===")
print(f"Packets sent: {COUNT}")
print(f"Duration: {duration:.3f} s")
print(f"Approx. send throughput: {throughput_mbps:.2f} Mbps")
print("================================")
