# net/netlink/ — Netlink Message Machinery

The netlink side of the socket layer: the core message-construction engine plus the two per-family/per-subsystem grammar registries. The AF_NETLINK *socket* helpers (`grammar_netlink`, `grammar_xfrm`) live in `net/proto/`; this dir builds the *message bodies* those sockets carry — nlmsg framing, rtnetlink payloads, and the generic-netlink (genl) and netfilter-netlink (nfnl) command/attribute grammars.

## Core message plumbing (this dir)

| File | Lines | Role |
|---|---|---|
| msg-rtnl-payloads.c | 2283 | Largest file in net/: five rtnetlink payload generators (`gen_rta_{route,link,addr,neigh,dcb}_payload`), carved out of msg.c for compile-unit size. File-static helpers (`rand_ipv4`, `start_nlattr`, `build_nested_attrs`) shared only within this TU. |
| msg.c | 1757 | `netlink_gen_msg()` (the `gen_msg` hook wired into `proto_netlink`): nlmsg flag/type generation, dispatch to the rtnl payload builders and the genl/nfnl grammars, occasional deliberate corruption of otherwise-valid messages. |
| msg-tables.c | 386 | Shared lookup/size tables consumed by the two above. |
| msg-internal.h | 169 | Private cross-TU declarations binding the three msg files together (not for outside inclusion). |

## Subdirectories
- [genl/](genl/CLAUDE.md) — generic-netlink family grammars (46 files: 45 per-family + the runtime registry).
- [nfnl/](nfnl/CLAUDE.md) — netfilter-netlink subsystem grammars (12 files: 11 per-subsystem + the registry).

## Key invariants
- **Registry-of-tables, repeated.** genl families and nfnl subsystems share one shape: a small `{cmd, name}` + `{attr, kind, size}` table per unit, and a central registry (`genl/families.c`, `nfnl/subsystems.c`) resolves/dispatches by ID at runtime.
- **Attribute shapes are policy-mirrored** — sized/typed to match the kernel's own `nla_policy` so messages reach the real command parser instead of bouncing at `-EINVAL`. Comments frequently cite the specific CVE or validation gate an attribute shape targets.
- **genl family-id is dynamic** (resolved at runtime via `CTRL_CMD_GETFAMILY`); nfnl subsystem id is a compile-time `NFNL_SUBSYS_*` constant — hence genl needs the runtime registry, nfnl's is simpler.

## Interactions
- `netlink_gen_msg` is wired into `net/proto/netlink.c`'s `proto_netlink`.
- Grammars are wired by extern struct (`fam_*`, subsystem grammars), consumed by the message generator and by `childops/genetlink-fuzzer.c` (which does independent runtime discovery, decoupled from `genl/families.c`).
- Conditional compilation: each genl family's `extern`/registry entry is gated by `__has_include()` against kernel UAPI headers, so coverage degrades gracefully on older kernels.
