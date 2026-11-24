"""Deterministic FRRouting Dual-ISP BGP + BFD configuration auditor (stdlib only)."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditFinding:
    rule_id: str
    severity: str  # "PASS" | "FAIL" | "WARN"
    message: str


@dataclass
class AuditReport:
    target: str
    ok: bool
    passed: int
    failed: int
    warnings: int
    metrics: dict[str, Any] = field(default_factory=dict)
    findings: list[AuditFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "ok": self.ok,
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings,
            "metrics": self.metrics,
            "findings": [asdict(f) for f in self.findings],
        }


def parse_daemons(daemons_text: str) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for raw in daemons_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        val = v.strip().strip('"').strip("'").lower()
        if val in ("yes", "no"):
            result[k.strip()] = val == "yes"
    return result


def parse_frr_config(conf_text: str) -> dict[str, Any]:
    """Parse relevant BGP, BFD, route-map, prefix-list, and static route blocks from frr.conf."""
    parsed: dict[str, Any] = {
        "local_as": None,
        "ebgp_requires_policy": False,
        "null0_routes": [],
        "prefix_lists": {},
        "bfd_profiles": {},
        "route_maps": {},
        "neighbors": {},
        "networks": [],
    }

    section: str | None = None
    cur_bfd_profile: str | None = None
    cur_rmap: str | None = None
    in_bgp = False

    for raw in conf_text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            if stripped == "!":
                if section == "bfd_profile":
                    section = "bfd"
                    cur_bfd_profile = None
                elif section in ("route_map", "bfd"):
                    section = None
                    cur_rmap = None
            continue

        # Top-level directives
        m_null = re.match(r"^(?:ip|ipv6)\s+route\s+(\S+)\s+(?:Null0|blackhole)\b", stripped, re.I)
        if m_null:
            parsed["null0_routes"].append(m_null.group(1))
            continue

        m_pl = re.match(r"^(?:ip|ipv6)\s+prefix-list\s+(\S+)\s+seq\s+\d+\s+(permit|deny)\s+(.+)$", stripped)
        if m_pl:
            parsed["prefix_lists"].setdefault(m_pl.group(1), []).append(
                {"action": m_pl.group(2), "prefix": m_pl.group(3).strip()}
            )
            continue

        if stripped == "bfd":
            section = "bfd"
            in_bgp = False
            continue

        m_bprof = re.match(r"^profile\s+(\S+)$", stripped)
        if section in ("bfd", "bfd_profile") and m_bprof:
            section = "bfd_profile"
            cur_bfd_profile = m_bprof.group(1)
            parsed["bfd_profiles"][cur_bfd_profile] = {}
            continue

        if section == "bfd_profile" and cur_bfd_profile:
            m_kv = re.match(r"^(detect-multiplier|transmit-interval|receive-interval)\s+(\d+)$", stripped)
            if m_kv:
                parsed["bfd_profiles"][cur_bfd_profile][m_kv.group(1)] = int(m_kv.group(2))
                continue

        m_rm = re.match(r"^route-map\s+(\S+)\s+(permit|deny)\s+(\d+)$", stripped)
        if m_rm:
            section = "route_map"
            in_bgp = False
            cur_rmap = m_rm.group(1)
            parsed["route_maps"].setdefault(
                cur_rmap, {"prefix_lists": [], "local_pref": None, "as_path_prepend": []}
            )
            continue

        if section == "route_map" and cur_rmap:
            rm = parsed["route_maps"][cur_rmap]
            m_mpl = re.match(r"^match\s+(?:ip|ipv6)\s+address\s+prefix-list\s+(\S+)$", stripped)
            if m_mpl:
                rm["prefix_lists"].append(m_mpl.group(1))
            m_lp = re.match(r"^set\s+local-preference\s+(\d+)$", stripped)
            if m_lp:
                rm["local_pref"] = int(m_lp.group(1))
            m_pp = re.match(r"^set\s+as-path\s+prepend\s+(.+)$", stripped)
            if m_pp:
                rm["as_path_prepend"].extend(m_pp.group(1).split())
            continue

        m_bgp = re.match(r"^router\s+bgp\s+(\d+)$", stripped)
        if m_bgp:
            in_bgp = True
            section = "bgp"
            parsed["local_as"] = int(m_bgp.group(1))
            continue

        if in_bgp:
            if stripped == "bgp ebgp-requires-policy":
                parsed["ebgp_requires_policy"] = True
                continue
            m_net = re.match(r"^network\s+(\S+)$", stripped)
            if m_net:
                parsed["networks"].append(m_net.group(1))
                continue
            m_n = re.match(r"^neighbor\s+(\S+)\s+(.+)$", stripped)
            if m_n:
                peer, rest = m_n.group(1), m_n.group(2)
                nb = parsed["neighbors"].setdefault(
                    peer,
                    {
                        "remote_as": None,
                        "bfd": False,
                        "bfd_profile": None,
                        "rmap_in": None,
                        "rmap_out": None,
                        "max_prefix": None,
                    },
                )
                m_ras = re.match(r"^remote-as\s+(\d+)$", rest)
                if m_ras:
                    nb["remote_as"] = int(m_ras.group(1))
                elif rest == "bfd":
                    nb["bfd"] = True
                elif rest.startswith("bfd profile "):
                    nb["bfd"] = True
                    nb["bfd_profile"] = rest.split("bfd profile ", 1)[1].strip()
                else:
                    m_rm_dir = re.match(r"^route-map\s+(\S+)\s+(in|out)$", rest)
                    if m_rm_dir:
                        nb[f"rmap_{m_rm_dir.group(2)}"] = m_rm_dir.group(1)
                    m_mp = re.match(r"^maximum-prefix\s+(\d+)", rest)
                    if m_mp:
                        nb["max_prefix"] = int(m_mp.group(1))

    return parsed


def audit_frr_directory(config_dir: str | Path) -> AuditReport:
    """Audit an FRR edge-gw directory containing `frr.conf` and optional `daemons`."""
    cdir = Path(config_dir)
    frr_path = cdir / "frr.conf" if cdir.is_dir() else cdir
    daemons_path = (cdir / "daemons") if cdir.is_dir() else (cdir.parent / "daemons")

    conf_text = frr_path.read_text(encoding="utf-8")
    parsed = parse_frr_config(conf_text)
    findings: list[AuditFinding] = []

    # 1. Daemons check (bgpd + bfdd enabled)
    if daemons_path.exists():
        daemons = parse_daemons(daemons_path.read_text(encoding="utf-8"))
        if daemons.get("bgpd") and daemons.get("bfdd"):
            findings.append(AuditFinding("FRR-01", "PASS", "Both bgpd=yes and bfdd=yes are enabled in daemons."))
        else:
            findings.append(AuditFinding("FRR-01", "FAIL", "Both bgpd=yes and bfdd=yes must be enabled in daemons."))
    else:
        findings.append(AuditFinding("FRR-01", "WARN", "No daemons file found alongside frr.conf."))

    # 2. RFC 8212 ebgp-requires-policy
    if parsed["ebgp_requires_policy"]:
        findings.append(AuditFinding("BGP-01", "PASS", "RFC 8212 `bgp ebgp-requires-policy` is enforced."))
    else:
        findings.append(AuditFinding("BGP-01", "FAIL", "Missing `bgp ebgp-requires-policy` (risk of unintended route leak)."))

    local_as = parsed["local_as"]
    ebgp_peers = {
        p: nb for p, nb in parsed["neighbors"].items() if nb["remote_as"] and nb["remote_as"] != local_as
    }

    # 3. Dual-ISP redundancy (>= 2 eBGP peers)
    if len(ebgp_peers) >= 2:
        findings.append(AuditFinding("BGP-02", "PASS", f"Dual-ISP multi-homing verified ({len(ebgp_peers)} eBGP peers)."))
    else:
        findings.append(AuditFinding("BGP-02", "FAIL", f"Expected >= 2 eBGP uplinks, found {len(ebgp_peers)}."))

    # 4. Explicit inbound & outbound route-maps on all eBGP peers
    missing_rmaps = [p for p, nb in ebgp_peers.items() if not nb["rmap_in"] or not nb["rmap_out"]]
    if ebgp_peers and not missing_rmaps:
        findings.append(AuditFinding("BGP-03", "PASS", "Every eBGP neighbor has explicit inbound and outbound route-maps."))
    else:
        findings.append(AuditFinding("BGP-03", "FAIL", f"Missing in/out route-map on eBGP peers: {missing_rmaps}."))

    # 5. Anti-Transit Guard (every outbound route-map matches a defined prefix-list)
    bad_out_rmaps = []
    for peer, nb in ebgp_peers.items():
        rm_name = nb["rmap_out"]
        rm = parsed["route_maps"].get(rm_name or "")
        if not rm or not rm["prefix_lists"]:
            bad_out_rmaps.append(f"{peer}:{rm_name}")
        else:
            for pl in rm["prefix_lists"]:
                if pl not in parsed["prefix_lists"]:
                    bad_out_rmaps.append(f"{peer}:{rm_name}(missing_pl:{pl})")
    if ebgp_peers and not bad_out_rmaps:
        findings.append(AuditFinding("BGP-04", "PASS", "Anti-transit guard verified: all outbound route-maps filter via explicit prefix-lists."))
    else:
        findings.append(AuditFinding("BGP-04", "FAIL", f"Anti-transit violation (unfiltered outbound route-maps): {bad_out_rmaps}."))

    # 6. Primary vs Backup Local Preference asymmetry
    lps = []
    for nb in ebgp_peers.values():
        rm = parsed["route_maps"].get(nb["rmap_in"] or "")
        if rm and rm["local_pref"] is not None:
            lps.append(rm["local_pref"])
    if len(lps) >= 2 and max(lps) > min(lps):
        findings.append(AuditFinding("BGP-05", "PASS", f"Active/backup Local Preference asymmetry configured ({max(lps)} vs {min(lps)})."))
    else:
        findings.append(AuditFinding("BGP-05", "FAIL", f"Need distinct primary/backup local-preference values on uplinks (found {lps})."))

    # 7. Backup outbound AS-Path Prepend
    prepends = [
        rm["as_path_prepend"]
        for nb in ebgp_peers.values()
        for rm in [parsed["route_maps"].get(nb["rmap_out"] or "")]
        if rm and rm["as_path_prepend"]
    ]
    if prepends:
        findings.append(AuditFinding("BGP-06", "PASS", f"Backup return-path steering via AS-Path Prepend configured ({len(prepends)} peer(s))."))
    else:
        findings.append(AuditFinding("BGP-06", "FAIL", "No outbound `set as-path prepend` found on backup uplink."))

    # 8. BFD enabled on all eBGP peers + sub-second detection time (<= 1000 ms)
    no_bfd = [p for p, nb in ebgp_peers.items() if not nb["bfd"]]
    detection_ms: int | None = None
    if ebgp_peers and not no_bfd:
        worst_ms = 0
        for nb in ebgp_peers.values():
            prof = parsed["bfd_profiles"].get(nb["bfd_profile"] or "", {})
            mult = prof.get("detect-multiplier", 3)
            rx = prof.get("receive-interval", 300)
            tx = prof.get("transmit-interval", 300)
            worst_ms = max(worst_ms, mult * max(rx, tx))
        detection_ms = worst_ms
        if worst_ms <= 1000:
            findings.append(AuditFinding("BFD-01", "PASS", f"Sub-second BFD verified on all eBGP peers (detection = {worst_ms} ms)."))
        else:
            findings.append(AuditFinding("BFD-01", "FAIL", f"BFD detection time too slow ({worst_ms} ms > 1000 ms)."))
    else:
        findings.append(AuditFinding("BFD-01", "FAIL", f"BFD not enabled on eBGP peers: {no_bfd}."))

    # 9. Inbound maximum-prefix protection
    no_maxp = [p for p, nb in ebgp_peers.items() if not nb["max_prefix"]]
    if ebgp_peers and not no_maxp:
        findings.append(AuditFinding("BGP-07", "PASS", "All eBGP peers enforce `maximum-prefix` safety limits."))
    else:
        findings.append(AuditFinding("BGP-07", "FAIL", f"Missing `maximum-prefix` limit on peers: {no_maxp}."))

    # 10. Null0 aggregate anchor for announced networks
    unanchored = [n for n in parsed["networks"] if n not in parsed["null0_routes"]]
    if parsed["networks"] and not unanchored:
        findings.append(AuditFinding("BGP-08", "PASS", f"All announced aggregates ({parsed['networks']}) have Null0 anchor routes."))
    else:
        findings.append(AuditFinding("BGP-08", "FAIL", f"Announced prefixes missing Null0 anchor route: {unanchored}."))

    passed = sum(1 for f in findings if f.severity == "PASS")
    failed = sum(1 for f in findings if f.severity == "FAIL")
    warnings = sum(1 for f in findings if f.severity == "WARN")
    return AuditReport(
        target=str(frr_path),
        ok=(failed == 0),
        passed=passed,
        failed=failed,
        warnings=warnings,
        metrics={
            "local_as": local_as,
            "ebgp_peers": len(ebgp_peers),
            "bfd_detection_ms": detection_ms,
            "announced_networks": parsed["networks"],
        },
        findings=findings,
    )
