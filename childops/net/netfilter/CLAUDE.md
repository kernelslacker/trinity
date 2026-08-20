# childops/net/netfilter/ — Netfilter Childops

nftables + conntrack + flowtable + nfnetlink stress workloads.

## Files (5 .c here + 14 .c and 5 internal headers under `nftables/`)
- `nftables/` — nftables_churn cluster:
  `churn.c` is the dispatched orchestrator for netns setup,
  sub-mode picking, main table/traffic/teardown sequence.
  `builders.c`, `compat.c`, `dormant.c`, `fwd.c`, `l4frag.c`,
  `reject.c`, `xt.c`,
  and `exprs-{conn,data,hash,nat,set,stateful}.c` hold rule/expression
  builders and sub-mode sweeps. The shared cross-TU declarations are
  split across `internal.h` (the umbrella), `internal-compat.h`,
  `internal-state.h`, `internal-exprs.h`, `internal-builders.h` and
  `internal-stats.h`.
- `nf-conntrack-helper-churn.c` — conntrack helper churn.
- `ct-expect-realloc.c` — conntrack expectation-list hlist backpointer vs `nf_ct_ext_add()` krealloc race.
- `ipset-churn.c` — ipset set/member lifecycle churn.
- `flowtable-encap-vlan.c` — flowtable offload + VLAN encap.
- `nfnl-util.c` — shared nfnetlink message scaffolding.
