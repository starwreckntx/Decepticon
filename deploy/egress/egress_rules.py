#!/usr/bin/env python3
"""
egress_rules.py — turn the engagement network scope into a kernel egress ruleset.

This is the kernel backstop to KKI's *software* scope gate. KKI refuses an out-of-scope
target in policy; this makes the refusal hold even if a tool call somehow slips the software
gate (a bug, an ungoverned path, a compromised tool): the packet to an out-of-scope address
is dropped by netfilter and never leaves the box. Same `KKI_NETWORK_SCOPE` drives both, so
the allowlist has a single source of truth.

Default policy is DROP on egress; only loopback, established/related return traffic, the
designated DNS resolver(s), and the in-scope CIDRs are permitted. Everything else is dropped
(and rate-limited-logged for the audit).

Usage:
    python3 egress_rules.py --scope 192.168.56.0/24,10.10.0.0/16 [--dns 1.1.1.1] \
        [--chain output|forward] [--format nft|iptables]
    # scope also read from $KKI_NETWORK_SCOPE when --scope is omitted.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from typing import List, Optional


def _parse_scope(raw: Optional[str]) -> List[str]:
    raw = raw if raw is not None else os.environ.get("KKI_NETWORK_SCOPE", "")
    cidrs: List[str] = []
    for tok in raw.replace(" ", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        # Validate + normalize; a bad CIDR must fail loudly, never silently widen scope.
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError as e:
            raise SystemExit(f"egress_rules: invalid CIDR {tok!r}: {e}")
        cidrs.append(str(net))
    if not cidrs:
        raise SystemExit("egress_rules: empty scope. Set --scope or KKI_NETWORK_SCOPE — "
                         "refusing to emit an open ruleset.")
    return cidrs


def _split_v4_v6(cidrs: List[str]):
    v4 = [c for c in cidrs if ipaddress.ip_network(c).version == 4]
    v6 = [c for c in cidrs if ipaddress.ip_network(c).version == 6]
    return v4, v6


def render_nft(cidrs: List[str], dns: List[str], chain: str) -> str:
    v4, v6 = _split_v4_v6(cidrs)
    hook = "output" if chain == "output" else "forward"
    lines = ["#!/usr/sbin/nft -f", "flush ruleset", "", "table inet kki_egress {"]
    if v4:
        lines += ["    set scope_v4 {", "        type ipv4_addr", "        flags interval",
                  "        elements = { " + ", ".join(v4) + " }", "    }"]
    if v6:
        lines += ["    set scope_v6 {", "        type ipv6_addr", "        flags interval",
                  "        elements = { " + ", ".join(v6) + " }", "    }"]
    lines += [
        f"    chain {hook} {{",
        f"        type filter hook {hook} priority filter; policy drop;",
        '        oif "lo" accept',
        "        ct state established,related accept",
    ]
    for d in dns:
        fam = "ip" if ipaddress.ip_address(d).version == 4 else "ip6"
        lines.append(f"        {fam} daddr {d} udp dport 53 accept")
        lines.append(f"        {fam} daddr {d} tcp dport 53 accept")
    if v4:
        lines.append("        ip daddr @scope_v4 accept")
    if v6:
        lines.append("        ip6 daddr @scope_v6 accept")
    lines += [
        '        limit rate 5/minute log prefix "KKI-EGRESS-DROP " level warn',
        "        counter comment \"out-of-scope egress dropped\"",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


def render_iptables(cidrs: List[str], dns: List[str], chain: str) -> str:
    v4, _ = _split_v4_v6(cidrs)
    c = "OUTPUT" if chain == "output" else "FORWARD"
    out = ["*filter", f":{c} DROP [0:0]",
           f"-A {c} -o lo -j ACCEPT",
           f"-A {c} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"]
    for d in dns:
        out.append(f"-A {c} -d {d} -p udp --dport 53 -j ACCEPT")
        out.append(f"-A {c} -d {d} -p tcp --dport 53 -j ACCEPT")
    for cidr in v4:
        out.append(f"-A {c} -d {cidr} -j ACCEPT")
    out.append(f"-A {c} -m limit --limit 5/min -j LOG --log-prefix \"KKI-EGRESS-DROP \"")
    out.append("COMMIT")
    out.append("")
    return "\n".join(out)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Generate a kernel egress ruleset from the engagement scope.")
    p.add_argument("--scope", help="comma-separated CIDRs (default: $KKI_NETWORK_SCOPE)")
    p.add_argument("--dns", default="", help="comma-separated DNS resolver IPs to permit (optional)")
    p.add_argument("--chain", choices=["output", "forward"], default="output",
                   help="output = jail this host's own traffic; forward = egress gateway/sidecar")
    p.add_argument("--format", choices=["nft", "iptables"], default="nft")
    args = p.parse_args(argv)

    cidrs = _parse_scope(args.scope)
    dns = [d.strip() for d in args.dns.split(",") if d.strip()]
    for d in dns:
        ipaddress.ip_address(d)  # validate

    if args.format == "nft":
        sys.stdout.write(render_nft(cidrs, dns, args.chain))
    else:
        sys.stdout.write(render_iptables(cidrs, dns, args.chain))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
