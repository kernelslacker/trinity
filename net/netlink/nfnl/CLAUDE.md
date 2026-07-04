# net/netlink/nfnl/ — Netfilter Netlink Subsystem Grammars

One file per netfilter-netlink (NFNL) subsystem, plus the registry. Same `{cmd, attrs}` table pattern as `genl/`, but simpler: `NFNL_SUBSYS_*` is a compile-time constant, so no dynamic family-id resolution is needed.

## Files (12 files)
- `subsystems.c` (160) — per-subsystem registry; stamps each grammar's stats counter into the shared arena.
- 11 per-subsystem files (`nftables.c`, `nft-compat.c`, `ctnetlink.c`, `cttimeout.c`, `cthelper.c`, `ipset.c`, `nfqueue.c`, `acct.c`, `osf.c`, `ulog.c`, `hook.c`), 59–127 lines each.

## Notes
- Attribute shapes mirror the kernel `nla_policy`; wired by extern struct, collected by `subsystems.c`. Link-time, no path coupling.
