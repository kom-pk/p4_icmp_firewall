#!/usr/bin/env python3

import subprocess
import re
import time

def collect_data(host, target_ip, test_type):
    # Start tcpdump to capture packets (ICMP only)
    tcpdump_proc = subprocess.Popen(['tcpdump', '-i', 'h1-eth0', '-c', '200', 'icmp'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)  # Give tcpdump time to start

    # Prompt to run ping manually
    print(f"Run 'ping {target_ip} -c 100' in xterm on {host} now...")
    time.sleep(1)  # Wait for you to start ping

    # Wait for ping to complete (assume ~10-15s for 100 pings)
    time.sleep(15)

    # Stop tcpdump and get output
    tcpdump_proc.terminate()
    tcpdump_output, _ = tcpdump_proc.communicate()
    tcpdump_lines = tcpdump_output.decode().splitlines()

    # Parse tcpdump for sent and received packets (approximate via ICMP echoes)
    sent_packets = sum(1 for line in tcpdump_lines if 'echo request' in line.lower())
    received_packets = sum(1 for line in tcpdump_lines if 'echo reply' in line.lower())
    dropped_packets = sent_packets - received_packets if sent_packets > received_packets else 0

    # Capture ping output (paste the last line manually)
    print(f"After ping, paste the last line of 'ping {target_ip}' output (e.g., '100 packets transmitted...') and press Enter:")
    ping_stats = input().strip()
    rtt_match = re.search(r'(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)', ping_stats)
    avg_rtt = float(rtt_match.group(2)) if rtt_match else 0.0  # Avg RTT from ping

    # Save results
    with open(f'{host}_{test_type}_baseline.txt', 'w') as f:
        f.write(f"Test Type: {test_type}\n")
        f.write(f"Target IP: {target_ip}\n")
        f.write(f"Sent Packets: {sent_packets}\n")
        f.write(f"Received Packets: {received_packets}\n")
        f.write(f"Dropped Packets: {dropped_packets}\n")
        f.write(f"Average RTT (ms): {avg_rtt}\n")
    print(f"Data saved to {host}_{test_type}_baseline.txt")

def main():
    host = "h1"  # Adjust based on xterm (h1 or h2)
    
    # P4 tests
    print("Switch to P4 topology and press Enter to start P4 tests...")
    input()
    collect_data(host, '10.0.2.30', 'P4_h1_h3')  # h1 to h3
    collect_data(host, '10.0.2.40', 'P4_h1_h4')  # h1 to h4

   

    # Repeat for h2 if needed (copy script to h2 xterm and adjust host)
    # For h2, change host to "h2" and targets to h3/h4

if __name__ == '__main__':
    main()
