# childops/net/netlink/ — Netlink Control-Plane Childops

Generic-netlink and rtnetlink control-plane fuzzers, plus shared netlink scaffolding.

## Files (14 .c + 1 internal header)
- `genetlink-fuzzer.c` / `genl-util.c` — generic-netlink family fuzzer + shared helpers.
- `nl80211-churn.c` — nl80211 (wifi) genl churn, split one phase per TU: `nl80211-churn-discovery.c` (discovery/setup), `nl80211-churn-iface.c` (interface churn), `nl80211-churn-scan.c` (scan/BSS + regdom), `nl80211-churn-station.c` (station/key). `nl80211-churn-internal.h` holds the shared declarations.
- `netlink-monitor-race.c` / `netlink-util.c` — netlink monitor race + shared helpers.
- `devlink-port-churn.c` — devlink port churn.
- `rtnl-vf-broadcast-getlink.c` — rtnetlink VF broadcast GETLINK.
- `handshake-req-abort.c` — handshake genl request abort.
- `altname-thrash.c` — rtnetlink IFLA_ALT_IFNAME prop-list UAF probe.
- `netconf-getdevconf-inetdev-teardown-race.c` — race RTM_GETNETCONF against concurrent IPv4 in_device teardown via RTM_DELLINK.
