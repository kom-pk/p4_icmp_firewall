#!/usr/bin/env python3
"""
Mininet topology that mirrors the P4 ICMP firewall testbed but uses a Linux
host running netfilter/iptables to enforce the same policy. The layout is:

    h1,h2 (internal) <-- s1 -- fw -- s2 --> h3,h4 (external)

The firewall host has two interfaces (fw-eth0, fw-eth1) with IPv4 forwarding
enabled. iptables rules implement:
  * default-drop stance for INPUT/FORWARD
  * stateful inspection via conntrack
  * optional rate limiting for inbound ICMP from the external side
  * optional source-based whitelisting loaded from config/whitelist.txt
"""

from __future__ import annotations

import argparse
import sys
from functools import partial
from pathlib import Path
from typing import Iterable, List, Optional

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import Host, OVSKernelSwitch
from mininet.topo import Topo


CONFIG_DIR = Path(__file__).parent / "config"
WHITELIST_PATH = CONFIG_DIR / "whitelist.txt"
RECENT_LIST_NAME = "icmp_inbound"


class NetfilterTopo(Topo):
    """Two-subnet topology with a firewall host in the middle."""

    def build(self) -> None:
        # Switches for the internal and external segments
        s_internal = self.addSwitch("s1")
        s_external = self.addSwitch("s2")

        # Internal hosts
        self.addHost(
            "h1",
            ip="10.0.1.10/24",
            defaultRoute="via 10.0.1.1",
        )
        self.addHost(
            "h2",
            ip="10.0.1.20/24",
            defaultRoute="via 10.0.1.1",
        )

        # External hosts
        self.addHost(
            "h3",
            ip="10.0.2.30/24",
            defaultRoute="via 10.0.2.1",
        )
        self.addHost(
            "h4",
            ip="10.0.2.40/24",
            defaultRoute="via 10.0.2.1",
        )

        # Transit routers (simple IPv4 forwarders)
        self.addHost("r1", ip="0.0.0.0")
        self.addHost("r2", ip="0.0.0.0")

        # Firewall host with two interfaces (IPs set post-start)
        self.addHost(
            "fw",
            ip="0.0.0.0",
        )

        # Wire up the topology
        self.addLink("h1", s_internal)
        self.addLink("h2", s_internal)
        self.addLink("r1", s_internal)
        self.addLink("r1", "fw")

        self.addLink("fw", "r2")
        self.addLink("r2", s_external)
        self.addLink("h3", s_external)
        self.addLink("h4", s_external)


def ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(exist_ok=True)
    if not WHITELIST_PATH.exists():
        WHITELIST_PATH.write_text("# One IPv4 address per line (e.g., 10.0.2.30)\n")


def load_whitelist(path: Path) -> List[str]:
    """Read newline-delimited IP addresses, ignoring comments/blanks."""
    entries: List[str] = []
    if not path.exists():
        return entries
    for line in path.read_text().splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped:
            entries.append(stripped)
    return entries


def run_cmds(host: Host, commands: Iterable[str]) -> None:
    """Execute a series of shell commands on the Mininet host."""
    for cmd in commands:
        result = host.cmd(cmd)
        if result:
            sys.stdout.write(result)


def configure_transit_nodes(net: Mininet) -> None:
    """Configure intermediary routers between the internal network and firewall."""
    r1: Host = net.get("r1")
    r2: Host = net.get("r2")

    # Configure r1 (internal gateway)
    r1.setIP("10.0.1.1/24", intf="r1-eth0")
    r1.setIP("10.0.10.1/30", intf="r1-eth1")
    run_cmds(
        r1,
        [
            "sysctl -w net.ipv4.ip_forward=1",
            "sysctl -w net.ipv4.conf.all.rp_filter=0",
            "sysctl -w net.ipv4.conf.r1-eth0.rp_filter=0",
            "sysctl -w net.ipv4.conf.r1-eth1.rp_filter=0",
            "ip route add 10.0.2.0/24 via 10.0.10.2",
            "ip route add 10.0.20.0/30 via 10.0.10.2",
        ],
    )

    # Configure r2 (external gateway)
    r2.setIP("10.0.20.1/30", intf="r2-eth0")
    r2.setIP("10.0.2.1/24", intf="r2-eth1")
    run_cmds(
        r2,
        [
            "sysctl -w net.ipv4.ip_forward=1",
            "sysctl -w net.ipv4.conf.all.rp_filter=0",
            "sysctl -w net.ipv4.conf.r2-eth0.rp_filter=0",
            "sysctl -w net.ipv4.conf.r2-eth1.rp_filter=0",
            "ip route add 10.0.1.0/24 via 10.0.20.2",
            "ip route add 10.0.10.0/30 via 10.0.20.2",
        ],
    )


def configure_firewall_host(
    net: Mininet, whitelist: List[str], threshold: Optional[int]
) -> None:
    """Assign addresses, enable forwarding, and provision iptables."""
    fw: Host = net.get("fw")

    # Assign interface addresses explicitly.
    fw.setIP("10.0.10.2/30", intf="fw-eth0")
    fw.setIP("10.0.20.2/30", intf="fw-eth1")

    # Enable IPv4 forwarding and disable reverse path filtering to simplify testing.
    run_cmds(
        fw,
        [
            "sysctl -w net.ipv4.ip_forward=1",
            "sysctl -w net.ipv4.conf.all.rp_filter=0",
            "sysctl -w net.ipv4.conf.fw-eth0.rp_filter=0",
            "sysctl -w net.ipv4.conf.fw-eth1.rp_filter=0",
            "ip route add 10.0.1.0/24 via 10.0.10.1",
            "ip route add 10.0.2.0/24 via 10.0.20.1",
        ],
    )

    # Reset firewall state before applying policy.
    reset_cmds = [
        "iptables -F",
        "iptables -X",
        "iptables -Z",
        "iptables -t nat -F",
        "iptables -t mangle -F",
    ]
    run_cmds(fw, reset_cmds)

    base_policy_cmds = [
        "iptables -P INPUT DROP",
        "iptables -P FORWARD DROP",
        "iptables -P OUTPUT ACCEPT",
        # Basic hygiene rules for the firewall host itself
        "iptables -A INPUT -i lo -j ACCEPT",
        "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A INPUT -i fw-eth0 -p icmp -j ACCEPT",
        # Allow internal hosts to originate ICMP
        (
            "iptables -A FORWARD -i fw-eth0 -o fw-eth1 "
            "-p icmp --icmp-type echo-request -j ACCEPT"
        ),
        # Build a custom chain for inbound ICMP control logic
        "iptables -N FW_ICMP_IN",
        (
            "iptables -A FORWARD -i fw-eth1 -o fw-eth0 "
            "-p icmp -j FW_ICMP_IN"
        ),
        # Stateful forwarding (must be last so inbound ICMP hits FW_ICMP_IN before returning)
        "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]
    run_cmds(fw, base_policy_cmds)

    # Insert whitelist entries into the inbound ICMP chain.
    limiter_enabled = threshold is not None and threshold > 0
    if limiter_enabled:
        # Ensure the recent list starts clean for every run.
        run_cmds(
            fw,
            [
                "modprobe xt_recent >/dev/null 2>&1 || true",
                (
                    f"if [ -w /proc/net/xt_recent/{RECENT_LIST_NAME} ]; then "
                    f"echo clear > /proc/net/xt_recent/{RECENT_LIST_NAME}; fi"
                ),
            ],
        )

    for ip in whitelist:
        rules: List[str] = []
        rules.append(
            (
                "iptables -A FW_ICMP_IN "
                f"-s {ip} -p icmp --icmp-type echo-request -j ACCEPT"
            )
        )
        rules.append(
            (
                "iptables -A FW_ICMP_IN "
                f"-s {ip} -p icmp --icmp-type echo-reply -j ACCEPT"
            )
        )
        run_cmds(fw, rules)

    if limiter_enabled:
        limiter_rules = [
            (
                "iptables -A FW_ICMP_IN "
                f"-m recent --name {RECENT_LIST_NAME} --rcheck "
                f"--hitcount {threshold} -j DROP"
            ),
            (
                "iptables -A FW_ICMP_IN -p icmp --icmp-type echo-request "
                f"-m recent --name {RECENT_LIST_NAME} --set -j ACCEPT"
            ),
            (
                "iptables -A FW_ICMP_IN -p icmp --icmp-type echo-reply "
                "-m conntrack --ctstate ESTABLISHED,RELATED "
                f"-m recent --name {RECENT_LIST_NAME} --set -j RETURN"
            ),
        ]
        run_cmds(fw, limiter_rules)
    else:
        run_cmds(
            fw,
            [
                (
                    "iptables -A FW_ICMP_IN -p icmp --icmp-type echo-reply "
                    "-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
                )
            ],
        )

    # Drop all other inbound ICMP traffic.
    run_cmds(fw, ["iptables -A FW_ICMP_IN -j DROP"])


def start_network(threshold: Optional[int]) -> None:
    ensure_config_dir()
    whitelist = load_whitelist(WHITELIST_PATH)

    topo = NetfilterTopo()
    net = Mininet(
        topo=topo,
        switch=partial(OVSKernelSwitch, failMode="standalone"),
        link=TCLink,
        controller=None,
        build=True,
    )
    net.start()

    try:
        configure_transit_nodes(net)
        configure_firewall_host(net, whitelist=whitelist, threshold=threshold)
        threshold_text = (
            f"{threshold} inbound ICMP packets per non-whitelisted source"
            if threshold and threshold > 0
            else "disabled (non-whitelisted sources permit unlimited inbound ICMP)"
        )
        print(
            "\nNetfilter topology running. Use the Mininet CLI to run tests.\n"
            "Key facts:\n"
            "  Internal hosts: h1 (10.0.1.10), h2 (10.0.1.20)\n"
            "  External hosts: h3 (10.0.2.30), h4 (10.0.2.40)\n"
            "  Transit routers: r1 (10.0.1.1 <-> 10.0.10.1), "
            "r2 (10.0.20.1 <-> 10.0.2.1)\n"
            "  Firewall host: fw (fw-eth0=10.0.10.2, fw-eth1=10.0.20.2)\n"
            f"  Inbound ICMP whitelist threshold: {threshold_text}\n"
            f"  Whitelist entries applied: {whitelist or 'none'}\n"
            f"  Whitelist file: {WHITELIST_PATH}\n"
        )
        CLI(net)
    finally:
        net.stop()


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Launch a Mininet topology with a netfilter/iptables firewall "
            "mirroring the P4 ICMP experiment."
        )
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help=(
            "Maximum inbound ICMP echo-requests per non-whitelisted source "
            "before packets are dropped (default: 10). "
            "Set to 0 to disable the cap."
        ),
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    start_network(threshold=args.threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
