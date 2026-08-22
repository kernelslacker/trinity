# childops/net/netlink/ — Netlink Scaffolding

Shared netlink plumbing. No dispatched op lives here any more.

## Files (1)
- `netlink-util.c` — netlink socket setup, sequence tracking, send/recv with
  ack handling, and `ns_since()` (a monotonic-clock delta helper used by the
  surviving childops).
