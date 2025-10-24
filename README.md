# Netfilter Benchmark Environment

This directory contains a Mininet-based replica of the P4 ICMP firewall testbed, using a Linux host with netfilter/iptables to enforce the policy. Use it to compare performance, correctness, and resource usage against the P4 dataplane implementation.

## Topology Overview

```
10.0.1.0/24 (internal)    10.0.10.0/30        10.0.20.0/30    10.0.2.0/24 (external)
  h1: 10.0.1.10 ---\         r1-eth1=10.0.10.1  fw-eth1=10.0.20.2   r2-eth1=10.0.2.1   /--- h3: 10.0.2.30
  h2: 10.0.1.20 ---- s1 -- r1 ---------------- fw --------------- r2 ---- s2 ---- h4: 10.0.2.40
                         r1-eth0=10.0.1.1      fw-eth0=10.0.10.2   r2-eth0=10.0.20.1
```

- `r1` and `r2` are plain Linux routers that forward traffic between the hosts and the firewall.
- `fw` runs iptables with a default-drop stance.
- Stateful inspection is handled by conntrack (`ESTABLISHED,RELATED`).
- `FW_ICMP_IN` chain enforces inbound ICMP:
  - Source whitelist (from `config/whitelist.txt`).
  - Per-source counter for non-whitelisted sources (default: allow 10 echo-requests, drop the rest).
  - Final drop rule.
- End-to-end paths now cross r1 → fw → r2, so ICMP TTL from h1 to h3/h4 arrives as 61 (matching the P4 testbed).

## Requirements

- Mininet (tested with 2.3.0).
- Python 3.8+.
- `iptables` and `conntrack` modules available on the host.
- Run with sudo/root privileges (`sudo python3 iptables_topology.py`).

## Quickstart

```bash
cd /home/kompk/Desktop/research
sudo python3 iptables_topology.py
```

In the Mininet CLI you can run the benchmark traffic:

- Baseline latency: `h1 ping -c 50 h3`
- Spoofed echo reply attempt: `h3 python3 - <<'PY' ...`
- Flood (20 pkt/s): `h3 python3 flood.py` (see example below)
- Dynamic whitelist: edit `config/whitelist.txt`, then rerun the topology or execute `fw iptables -I FW_ICMP_IN 1 -s 10.0.2.30 -j ACCEPT`

Exit the CLI with `exit`.

## Adjusting the Inbound Threshold

Each non-whitelisted external source may originate up to 10 inbound ICMP echo-requests before further probes are dropped (mirroring the P4 firewall counter). To change the allowance, set `--threshold` when launching:

```bash
sudo python3 iptables_topology.py --threshold 5
```

Use `--threshold 0` to disable the cap and permit unlimited probes for non-whitelisted hosts.

## Whitelisting External Sources

Add IPv4 addresses to `config/whitelist.txt` (one per line). The file is read at startup and each entry is inserted at the top of `FW_ICMP_IN`. Whitelisted hosts now bypass the rate limiter entirely, so they retain full ICMP access regardless of the `--threshold` setting.

```
# config/whitelist.txt
10.0.2.30
```

To update without restarting, use the Mininet CLI:

```
mininet> fw iptables -I FW_ICMP_IN 1 -s 10.0.2.30 -p icmp --icmp-type echo-request -j ACCEPT
```

