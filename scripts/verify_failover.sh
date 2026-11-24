#!/usr/bin/env bash
set -euo pipefail

echo "=== 1. Verify initial BGP + BFD convergence on edge-gw ==="
docker exec frr-edge-gw vtysh -c "show bgp ipv4 unicast summary"
docker exec frr-edge-gw vtysh -c "show bfd peers brief"
docker exec frr-edge-gw vtysh -c "show ip route 203.0.113.0/24"

echo ""
echo "=== 2. Verify anti-transit & AS-Path prepend toward ISP2 ==="
docker exec frr-isp2-backup vtysh -c "show bgp ipv4 unicast 198.51.100.0/24"

echo ""
echo "=== 3. Inject silent L2/L3 blackhole on ISP1 (drop BFD UDP 3784 + BGP TCP 179 without link-down) ==="
T0=$(date +%s%3N)
docker exec frr-isp1-primary iptables -I INPUT -s 10.255.1.1 -j DROP
docker exec frr-isp1-primary iptables -I OUTPUT -d 10.255.1.1 -j DROP

while true; do
  ROUTE=$(docker exec frr-edge-gw vtysh -c "show ip route 203.0.113.0/24" 2>/dev/null || true)
  if echo "$ROUTE" | grep -q "10.255.2.2"; then
    T1=$(date +%s%3N)
    ELAPSED=$((T1 - T0))
    echo "FAILOVER_CONVERGED_TO_ISP2 in ${ELAPSED} ms!"
    echo "$ROUTE"
    break
  fi
  sleep 0.1
done

echo ""
echo "=== 4. Restore ISP1 and verify automatic preemption back to Local Preference 200 ==="
docker exec frr-isp1-primary iptables -D INPUT -s 10.255.1.1 -j DROP
docker exec frr-isp1-primary iptables -D OUTPUT -d 10.255.1.1 -j DROP
sleep 3
docker exec frr-edge-gw vtysh -c "show bfd peers brief"
docker exec frr-edge-gw vtysh -c "show ip route 203.0.113.0/24"
