"""CLI entrypoint for frr-dual-isp-failover-lab auditor & simulator."""

from __future__ import annotations

import argparse
import json
import sys

from .linter import audit_frr_directory
from .simulator import simulate_failover


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="frr_failover_audit",
        description="Zero-dependency FRRouting Dual-ISP BGP+BFD linter & failover simulator.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_lint = sub.add_parser("lint", help="Audit an FRR edge gateway config directory or frr.conf")
    p_lint.add_argument("target", help="Path to FRR config directory (e.g. configs/edge-gw) or frr.conf")
    p_lint.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    p_sim = sub.add_parser("simulate", help="Compare BGP-only vs BGP+BFD silent blackhole failover")
    p_sim.add_argument("--bgp-hold", type=int, default=180, help="BGP Hold Timer in seconds (default: 180)")
    p_sim.add_argument("--bfd-interval", type=int, default=300, help="BFD interval in ms (default: 300)")
    p_sim.add_argument("--bfd-mult", type=int, default=3, help="BFD detect multiplier (default: 3)")
    p_sim.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    args = parser.parse_args(argv)

    if args.cmd == "lint":
        report = audit_frr_directory(args.target)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(f"=== FRR Dual-ISP Audit: {report.target} ===")
            for f in report.findings:
                print(f"  [{f.severity:4s}] {f.rule_id}: {f.message}")
            print(
                f"SUMMARY: ok={report.ok} passed={report.passed} failed={report.failed} "
                f"bfd_detection_ms={report.metrics.get('bfd_detection_ms')}"
            )
        return 0 if report.ok else 2

    if args.cmd == "simulate":
        sim = simulate_failover(
            bgp_hold_timer_s=args.bgp_hold,
            bfd_interval_ms=args.bfd_interval,
            bfd_multiplier=args.bfd_mult,
        )
        if args.json:
            print(json.dumps(sim.to_dict(), indent=2))
        else:
            print("=== Silent-Blackhole Failover Comparison ===")
            print(f"  Scenario:           {sim.scenario}")
            print(f"  BGP-only ({sim.bgp_hold_timer_s}s hold): {sim.bgp_only_blackhole_ms:,} ms (~{sim.bgp_only_blackhole_ms/1000:.2f}s blackout)")
            print(f"  BGP + BFD ({sim.bfd_interval_ms}ms x {sim.bfd_multiplier}): {sim.bgp_with_bfd_failover_ms:,} ms (~{sim.bgp_with_bfd_failover_ms/1000:.2f}s failover)")
            print(f"  Speedup factor:     {sim.speedup_factor}x faster convergence")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
