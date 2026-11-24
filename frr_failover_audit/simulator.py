"""Deterministic Dual-ISP failover timeline simulator: BGP-only vs BGP + BFD."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class FailoverComparison:
    scenario: str
    bgp_hold_timer_s: int
    bfd_interval_ms: int
    bfd_multiplier: int
    bgp_only_blackhole_ms: int
    bgp_with_bfd_failover_ms: int
    speedup_factor: float
    packet_loss_at_1000pps_bgp_only: int
    packet_loss_at_1000pps_bfd: int

    def to_dict(self) -> dict:
        return asdict(self)


def simulate_failover(
    bgp_hold_timer_s: int = 180,
    bfd_interval_ms: int = 300,
    bfd_multiplier: int = 3,
    fib_reprogram_ms: int = 40,
    scenario: str = "Silent fiber cut beyond first L2 switch (no physical link-down)",
) -> FailoverComparison:
    """Compare silent-blackhole convergence times for standard BGP vs BGP + BFD."""
    if bgp_hold_timer_s <= 0 or bfd_interval_ms <= 0 or bfd_multiplier <= 0:
        raise ValueError("Timer and multiplier values must be positive integers.")

    bgp_only_ms = bgp_hold_timer_s * 1000 + fib_reprogram_ms
    bfd_failover_ms = (bfd_interval_ms * bfd_multiplier) + fib_reprogram_ms
    speedup = round(bgp_only_ms / bfd_failover_ms, 1)

    return FailoverComparison(
        scenario=scenario,
        bgp_hold_timer_s=bgp_hold_timer_s,
        bfd_interval_ms=bfd_interval_ms,
        bfd_multiplier=bfd_multiplier,
        bgp_only_blackhole_ms=bgp_only_ms,
        bgp_with_bfd_failover_ms=bfd_failover_ms,
        speedup_factor=speedup,
        packet_loss_at_1000pps_bgp_only=bgp_only_ms,
        packet_loss_at_1000pps_bfd=bfd_failover_ms,
    )
