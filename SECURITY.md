# Security Policy

- All IP ranges (`198.51.100.0/24`, `203.0.113.0/24`, `2001:db8:6501::/48`) and AS numbers (`65010`, `65100`, `65200`) in this lab strictly follow RFC 5737 / RFC 3849 / RFC 6996 documentation & private space.
- Never deploy raw lab configs to production without RPKI/ROA verification, GTSM/TTL security (`ttl-security hops 1`), and TCP-AO/MD5 BGP session authentication negotiated with your upstream ISPs.
- Security reports: `alexey.zhuykov@gmail.com` (Subject: `[SECURITY] frr-dual-isp-failover-lab`).
