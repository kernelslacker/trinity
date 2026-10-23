# net/netlink/nfnl/ — Netfilter Netlink Subsystem Grammars

One file per netfilter-netlink (NFNL) subsystem, plus the registry. Same `{cmd, attrs}` table pattern as `genl/`, but simpler: `NFNL_SUBSYS_*` is a compile-time constant, so no dynamic family-id resolution is needed.

## Files (12 .c files, ~1,106 LOC)
- `subsystems.c` (150) — per-subsystem registry; stamps each grammar's stats counter into the shared arena.
- 11 per-subsystem files (`nftables.c` 285, `ipset.c` 160, `ctnetlink.c` 125, `cttimeout.c` 95, `nfqueue.c` 49, `acct.c` 46, `ulog.c` 45, `cthelper.c` 42, `hook.c` 39, `osf.c` 38, `nft-compat.c` 32).

## Notes
- Attribute shapes mirror the kernel `nla_policy`; wired by extern struct, collected by `subsystems.c`. Link-time, no path coupling.
- `nfnetlink_rcv()` runs `netlink_net_capable(skb, CAP_NET_ADMIN)` on every message before it looks at the subsystem, so every command, GET and dump requests included, is answered `-EPERM` unless both the socket's opener and the sender hold CAP_NET_ADMIN in the user namespace that owns the socket's netns. The policy parse and the handlers sit behind that test and are reached only by a child that passes it; the cthelper and osf handlers then also require `capable(CAP_NET_ADMIN)`, the initial user namespace. Subsystem files name only what is specific to them.
- `nfnetlink_rcv_msg()` and the batch path parse the top-level attributes with the liberal `nla_parse_deprecated()` against the callback's policy: an id past `attr_count` is dropped, an id in an untyped slot is accepted unchecked, and a typed slot is length-checked. A flat-table attribute the picked command's policy lacks is therefore ignored (a strict-validating genl op answers `-EINVAL`), while one whose id another namespace of the same table types differently meets that type.
- In the subsystems here a nest is a bare `NLA_NESTED`, which `nla_validate()` does not look into, except five `NLA_POLICY_NESTED_ARRAY` entries in `nf_tables_api.c` (rule, set and set-element expressions, set-desc concat, set-element list). A bare nest is parsed, if at all, by the handler: `nla_parse_nested_deprecated()` against a per-type or per-L4 sub-policy, except in ipset (and ctnetlink's `CTA_FILTER`), where the strict `nla_parse_nested()` rejects a child the sub-policy lacks. `NLA_KIND_NESTED` specs are filled as `genl/CLAUDE.md` describes, one to three children from the same flat table, so the handlers see children whose ids are outer-namespace ids.
