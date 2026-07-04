# childops/net/netlink/ — Netlink Control-Plane Childops

Generic-netlink and rtnetlink control-plane fuzzers, plus shared netlink scaffolding.

## Files (9)
- `genetlink-fuzzer.c` / `genl-util.c` — generic-netlink family fuzzer + shared helpers.
- `nl80211-churn.c` — nl80211 (wifi) genl churn.
- `netlink-monitor-race.c` / `netlink-util.c` — netlink monitor race + shared helpers.
- `devlink-port-churn.c` — devlink port churn.
- `rtnl-vf-broadcast-getlink.c` — rtnetlink VF broadcast GETLINK.
- `handshake-req-abort.c` — handshake genl request abort.
- `altname-thrash.c` — rtnetlink IFLA_ALT_IFNAME prop-list UAF probe.
