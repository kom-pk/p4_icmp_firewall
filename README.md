# Netfilter vs P4 ICMP Firewall Benchmark

This repository contains the two environments we use to evaluate an ICMP-aware firewall policy: a Linux netfilter/iptables deployment and a P4 implementation targeting BMv2. Both topologies are Mininet-based and share the same logical layout, which lets you capture performance, correctness, and operational differences while holding the traffic patterns constant.

## Repository Layout
- `iptables/` – Python topology (`iptables_topology.py`) plus configuration files for the Linux-based firewall benchmark. See `iptables/README.md` for lower-level details.
- `p4/basic/` – P4 source (`myfirewall.p4`), build artifacts, runtime configs, and captured traces for the P4 dataplane version of the firewall.
- `p4/utils/` – Mininet helpers, runtime libraries, and scripts required by the P4 exercises (adapted from the p4lang tutorials).
- `p4/basic/scripts/` – Host-side helpers to collect baseline latency, throughput, and whitelist management data during experiments.
- `.ova` appliance – A VirtualBox image that ships all P4 dependencies, BMv2, and Mininet pre-installed. The image will be published with the GitHub release so researcher can reproduce the P4 setup without rebuilding toolchains.

## Host Requirements
Both environments assume a Linux host capable of running Mininet (Ubuntu 20.04+ recommended) with passwordless `sudo` or root access. The following packages are used across the testbeds:
- Python 3.8 or newer
- Mininet 2.3.x (with Open vSwitch support)
- `tcpdump`, `conntrack`, and `iptables` (for policy inspection and measurements)
- Optional: `scapy` for the custom traffic generators in `p4/basic/scripts`

## Linux Netfilter Firewall
The `iptables_topology.py` script reproduces the firewall topology with a software router on each side of the inspection point:

```
10.0.1.0/24 (h1, h2)  <-- r1 -->  fw  <-- r2 -->  10.0.2.0/24 (h3, h4)
```

- Stateless forwarding is handled by `r1` and `r2`, which are plain Mininet hosts with IPv4 forwarding enabled.
- The `fw` node applies a default-drop policy, stateful inspection via conntrack, per-source ICMP rate limiting (`--threshold`, default 10 requests), and whitelist entries drawn from `config/whitelist.txt`.

### Running the netfilter topology
```bash
cd iptables
sudo python3 iptables_topology.py --threshold 10
```
Inside the Mininet CLI:
- `h1 ping -c 50 h3` – baseline RTT/packet loss
- `fw iptables -L FW_ICMP_IN -v` – verify counters and whitelist hits
- Edit `config/whitelist.txt`, then restart the topology (or manually insert rules) to test privileged sources.

The script will create the `config/` directory on first run and populate a commented `whitelist.txt`. Outputs such as conntrack state, rate-limit hits, and per-interface counters can be harvested directly from the CLI using standard Linux tooling.

## P4 ICMP Firewall
The P4 version of the firewall lives in `p4/basic/`:
- `myfirewall.p4` extends the tutorial baseline to enforce ICMP request throttling and whitelist behavior that mirrors the netfilter rules.
- `pod-topo/*` defines the same logical topology and the P4Runtime JSON intended for BMv2.
- `build/` captures compiler output (`*.json`, `*.p4info.txt`) for reproducibility.
- `logs/` and `pcaps/` store control-plane traces and packet captures from recent experiments.

### Running the P4 topology
```bash
cd p4/basic
make run         # compiles myfirewall.p4, launches Mininet, installs runtime rules
```

Key commands once the topology is live:
- `h1 ping -c 50 h3` – confirm baseline connectivity and TTL parity with the netfilter setup.
- `sudo ./scripts/add_whitelist <IP>` – inject a runtime whitelist entry through the control plane.
- `sudo ./scripts/collect_baseline.py` – guided workflow to mirror the measurement process used on the Linux stack (requires `tcpdump`).
- `sudo ./scripts/icmp_thruput.py` – fire an ICMP burst to measure throughput under load (requires `scapy` inside the host namespace).

Use `make stop` to tear down Mininet and `make clean` to purge build and capture artifacts.

## Comparative Workflow
1. **Baseline connectivity:** Run equivalent `ping` tests in each environment to establish RTT and packet loss under normal load.
2. **Whitelist validation:** Add entries in `config/whitelist.txt` (netfilter) or via `scripts/add_whitelist` (P4) to verify that trusted sources bypass throttling.
3. **Adversarial traffic:** Use the `icmp_thruput.py` script (or your own Scapy generators) to flood the firewall and observe rate caps. In the netfilter topology, replicate the load with `h3 python3 - <<'PY' ...` or an external generator.
4. **Data capture:** Store metrics produced by `collect_baseline.py`, `fw iptables -L ... -v`, and the P4 logs (`logs/s*-runtime-requests.txt`, `pcaps/`) to build the comparison dataset.

Document each run so you can attribute differences to the dataplane technology rather than environmental drift.

## Virtual Appliance (OVA) Delivery
A prepackaged `.ova` will be uploaded alongside this repository. Import it into VirtualBox or VMware, boot the VM, and use the included README inside the guest to launch the P4 firewall immediately. The VM contains:
- Prebuilt BMv2, P4C, and the tutorial utils aligned with this repo
- Mininet configured for nested virtualization where supported
- Scripts to sync the `p4/basic/` directory with this repository

Once the OVA artifact is live, update collaborators so they can reproduce your P4 results without rebuilding toolchains locally.

## Troubleshooting & Tips
- Use `sudo mn -c` if a previous Mininet session was interrupted.
- Both environments assume the host can reach `10.0.0.0/8` test networks; disable conflicting services or use network namespaces to avoid ARP collisions.
- Packet captures in `p4/basic/pcaps/` mirror the switch ports; compare them against `tcpdump` output from the netfilter run to spot policy discrepancies.
- If you modify `myfirewall.p4`, remember to adjust the runtime JSON files so table/action names stay in sync.

By keeping the topologies functionally identical, you can gather apples-to-apples results across the Linux and P4 dataplanes and attribute any variation to implementation differences rather than lab setup.
