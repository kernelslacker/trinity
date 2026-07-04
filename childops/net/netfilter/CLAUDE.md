# childops/net/netfilter/ — Netfilter Childops

nftables + conntrack + flowtable + nfnetlink stress workloads.

## Files (10 + internal header)
- `nftables-churn.c` + expr families `nftables-churn-exprs-{conn,data,hash,nat,set,stateful}.c` — nftables rule/expression churn. `nftables-churn-internal.h` holds the shared cross-TU declarations.
- `nf-conntrack-helper-churn.c` — conntrack helper churn.
- `flowtable-encap-vlan.c` — flowtable offload + VLAN encap.
- `nfnl-util.c` — shared nfnetlink message scaffolding.
