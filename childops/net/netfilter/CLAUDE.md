# childops/net/netfilter/ — Netfilter Childops

nftables + conntrack + flowtable + nfnetlink stress workloads.

## Files (17 + internal header)
- `nftables/` — nftables_churn cluster:
  `churn.c` is the dispatched orchestrator for netns setup,
  sub-mode picking, main table/traffic/teardown sequence.
  `builders.c`, `compat.c`, `dormant.c`, `fwd.c`, `l4frag.c`, `xt.c`,
  and `exprs-{conn,data,hash,nat,set,stateful}.c` hold rule/expression
  builders and sub-mode sweeps. `internal.h` holds the shared cross-TU
  declarations.
- `nf-conntrack-helper-churn.c` — conntrack helper churn.
- `flowtable-encap-vlan.c` — flowtable offload + VLAN encap.
- `nfnl-util.c` — shared nfnetlink message scaffolding.
