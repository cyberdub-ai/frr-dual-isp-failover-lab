"""Unit and CLI tests for frr_failover_audit (zero external dependencies)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from frr_failover_audit import audit_frr_directory, simulate_failover

REPO_ROOT = Path(__file__).resolve().parent.parent
EDGE_GW_DIR = REPO_ROOT / "configs" / "edge-gw"


class TestFRRFailoverAudit(unittest.TestCase):
    def test_shipped_edge_gw_passes_all_10_checks(self) -> None:
        report = audit_frr_directory(EDGE_GW_DIR)
        self.assertTrue(report.ok, f"Unexpected failures: {report.findings}")
        self.assertEqual(report.passed, 10)
        self.assertEqual(report.failed, 0)
        self.assertEqual(report.metrics["local_as"], 65010)
        self.assertEqual(report.metrics["ebgp_peers"], 2)
        self.assertEqual(report.metrics["bfd_detection_ms"], 900)

    def test_detects_missing_bfdd_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "daemons").write_text("bgpd=yes\nbfdd=no\n", encoding="utf-8")
            (p / "frr.conf").write_text((EDGE_GW_DIR / "frr.conf").read_text(encoding="utf-8"), encoding="utf-8")
            report = audit_frr_directory(p)
            self.assertFalse(report.ok)
            failed_ids = {f.rule_id for f in report.findings if f.severity == "FAIL"}
            self.assertIn("FRR-01", failed_ids)

    def test_detects_missing_ebgp_requires_policy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "daemons").write_text("bgpd=yes\nbfdd=yes\n", encoding="utf-8")
            conf = (EDGE_GW_DIR / "frr.conf").read_text(encoding="utf-8").replace("bgp ebgp-requires-policy", "")
            (p / "frr.conf").write_text(conf, encoding="utf-8")
            report = audit_frr_directory(p)
            failed_ids = {f.rule_id for f in report.findings if f.severity == "FAIL"}
            self.assertIn("BGP-01", failed_ids)

    def test_detects_accidental_transit_leak_when_outbound_prefix_list_removed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "daemons").write_text("bgpd=yes\nbfdd=yes\n", encoding="utf-8")
            conf = (EDGE_GW_DIR / "frr.conf").read_text(encoding="utf-8").replace(
                "match ip address prefix-list OWN-PREFIXES-OUT", ""
            )
            (p / "frr.conf").write_text(conf, encoding="utf-8")
            report = audit_frr_directory(p)
            failed_ids = {f.rule_id for f in report.findings if f.severity == "FAIL"}
            self.assertIn("BGP-04", failed_ids)

    def test_detects_slow_bfd_profile_over_1000ms(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "daemons").write_text("bgpd=yes\nbfdd=yes\n", encoding="utf-8")
            conf = (EDGE_GW_DIR / "frr.conf").read_text(encoding="utf-8").replace("transmit-interval 300", "transmit-interval 500")
            (p / "frr.conf").write_text(conf, encoding="utf-8")
            report = audit_frr_directory(p)
            failed_ids = {f.rule_id for f in report.findings if f.severity == "FAIL"}
            self.assertIn("BFD-01", failed_ids)
            self.assertEqual(report.metrics["bfd_detection_ms"], 1500)

    def test_detects_missing_local_preference_asymmetry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "daemons").write_text("bgpd=yes\nbfdd=yes\n", encoding="utf-8")
            conf = (EDGE_GW_DIR / "frr.conf").read_text(encoding="utf-8").replace("set local-preference 200", "set local-preference 100")
            (p / "frr.conf").write_text(conf, encoding="utf-8")
            report = audit_frr_directory(p)
            failed_ids = {f.rule_id for f in report.findings if f.severity == "FAIL"}
            self.assertIn("BGP-05", failed_ids)

    def test_detects_missing_null0_anchor_and_max_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "daemons").write_text("bgpd=yes\nbfdd=yes\n", encoding="utf-8")
            conf = (EDGE_GW_DIR / "frr.conf").read_text(encoding="utf-8")
            conf = conf.replace("ip route 198.51.100.0/24 Null0", "")
            conf = conf.replace("maximum-prefix 1000 80 restart 5", "description no-limit")
            (p / "frr.conf").write_text(conf, encoding="utf-8")
            report = audit_frr_directory(p)
            failed_ids = {f.rule_id for f in report.findings if f.severity == "FAIL"}
            self.assertIn("BGP-07", failed_ids)
            self.assertIn("BGP-08", failed_ids)

    def test_simulator_shows_subsecond_speedup(self) -> None:
        sim = simulate_failover(bgp_hold_timer_s=180, bfd_interval_ms=300, bfd_multiplier=3)
        self.assertEqual(sim.bgp_only_blackhole_ms, 180040)
        self.assertEqual(sim.bgp_with_bfd_failover_ms, 940)
        self.assertGreater(sim.speedup_factor, 190.0)

    def test_cli_lint_json_and_exit_code(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "frr_failover_audit", "lint", str(EDGE_GW_DIR), "--json"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["passed"], 10)

    def test_cli_simulate_json(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "frr_failover_audit", "simulate", "--json"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["bfd_interval_ms"], 300)
        self.assertEqual(data["bgp_with_bfd_failover_ms"], 940)


if __name__ == "__main__":
    unittest.main()
