# net/netlink/nfnl/ — Netfilter Netlink Subsystem Grammars

One file per netfilter-netlink (NFNL) subsystem, plus the registry. Same `{cmd, attrs}` table pattern as `genl/`, but simpler: `NFNL_SUBSYS_*` is a compile-time constant, so no dynamic family-id resolution is needed.

## Files (12 .c files, ~1,463 LOC)
- `subsystems.c` (160) — per-subsystem registry; stamps each grammar's stats counter into the shared arena.
- 11 per-subsystem files (`nftables.c` 304, `ipset.c` 232, `ctnetlink.c` 146, `cttimeout.c` 144, `cthelper.c` 81, `ulog.c` 70, `nfqueue.c` 70, `osf.c` 67, `acct.c` 67, `hook.c` 63, `nft-compat.c` 59).

## Notes
- Attribute shapes mirror the kernel `nla_policy`; wired by extern struct, collected by `subsystems.c`. Link-time, no path coupling.
