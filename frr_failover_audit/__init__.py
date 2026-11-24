"""Zero-dependency FRRouting BGP + BFD Dual-ISP policy linter and failover simulator."""

from .linter import AuditFinding, AuditReport, audit_frr_directory, parse_frr_config
from .simulator import FailoverComparison, simulate_failover

__all__ = [
    "AuditFinding",
    "AuditReport",
    "FailoverComparison",
    "audit_frr_directory",
    "parse_frr_config",
    "simulate_failover",
]
__version__ = "0.1.0"
