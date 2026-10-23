# net/netlink/ — Netlink Message Machinery

The netlink side of the socket layer: the core message-construction engine plus the two per-family/per-subsystem grammar registries. The AF_NETLINK *socket* helpers live in `net/proto/netlink.c`; this dir builds the *message bodies* those sockets carry — nlmsg framing, rtnetlink payloads, and the generic-netlink (genl) and netfilter-netlink (nfnl) command/attribute grammars.

## Core message plumbing (this dir — 13 .c files + 3 headers, ~6,389 LOC)

The engine is no longer one file: the emitter was carved into `msg-*.c`
behind `msg-internal.h`, and the rtnetlink payload builders were carved
again into one TU per RTM_* group behind `msg-rtnl-common.h`.

| File | Lines | Role |
|---|---|---|
| msg-rtnl-neigh.c | 905 | Largest file in net/: payload builders for the neighbour (NDA_*), neighbour-table (NDTA_*), bridge MDB (MDBA_*) and bridge VLAN DB (BRIDGE_VLANDB_*) groups. |
| msg-tables.c | 590 | Pure descriptor data: per-protocol message-type lists, per-rtnl-group nlattr-type lists, per-family `nla_attr_spec` tables, and the xfrm family-field offset table. Each table is paired with an `_n` size constant so emitters can index across the TU boundary without `ARRAY_SIZE()`. |
| msg-rtnl-tc.c | 607 | Payload builders for the tc (TCA_*), tc-action (TCA_ROOT_*) and link-stats (IFLA_STATS_*) groups. |
| msg-rtnl-route.c | 578 | Payload builders for the route / rule / nexthop / prefix / nsid / chain groups. |
| rtnl-ack-oracle.c | 400 | Sampled ACK oracle for NETLINK_ROUTE: on 1-in-N messages it ORs `NLM_F_ACK` into the header in place, then drains the `NLMSG_ERROR` reply *after* the real sendmsg and bins the outcome per nlmsg_type. Closes the gap where the nested-attr counter incremented identically whether the kernel accepted or discarded the message. |
| msg-attr-random.c | 480 | Legacy random-payload attribute emission for families with no curated spec table (chiefly NETLINK_ROUTE): `gen_rta_payload` and its nested classifier, the per-group attribute-type hint lists, and the two emitters `append_nlattr` / `append_nested_attr_container`. |
| msg-rtnl-link.c | 464 | Payload builders for the link (IFLA_*), link-property (RTM_*LINKPROP) and tunnel (RTM_*TUNNEL, vxlan-vnifilter) groups. |
| msg-rtnl-body.c | 412 | The fixed struct each RTM_* group carries between the nlmsghdr and its attributes (ifinfomsg, rtmsg, ndmsg, ...), filled with correctly-sized fuzzed fields so length/family validation lets the message through to the attribute walker. Also defines the shared `rand_family()`. |
| msg-core.c | 455 | `netlink_gen_msg()` (the `gen_msg` hook wired into `proto_netlink`): nlmsg flag/type generation (the 1-in-10 chaos roll lives in `build_one_nlmsg()`; for a genl message `gen_nlmsg_flags()` pins the dump bits to the picked cmd's doit/dumpit shape and draws the ATOMIC/NEW/DELETE modifiers one time in 8), `build_one_nlmsg()`, the attribute walker `iter_nlmsg_attr()`, and occasional deliberate corruption of otherwise-valid messages. |
| msg-proto-body.c | 362 | The per-protocol equivalent of msg-rtnl-body.c: `gen_{genl,nfnl,xfrm,audit,sockdiag}_body` size and fill the small fixed header each NETLINK_* family expects before its parser runs; `gen_genl_body()` also reports the picked cmd's doit/dumpit shape and leaves the reserved word 0 outside chaos messages. |
| msg-attr-spec.c | 289 | Spec-driven attribute emission for families that *do* have a curated `nla_attr_spec` table (XFRM, ctnetlink, nftables, genl-ctrl, sock_diag). `pick_spec_table()` selects the table or returns NULL to fall through to the random path. |
| msg-internal.h | 279 | Private cross-TU declarations binding the msg files together (not for outside inclusion). |
| msg-rtnl-payloads.c | 267 | The residual rtnetlink payload builders that were not carved into a per-group TU: addr, addrlabel, dcb, netconf. |
| msg-rtnl-common.c | 194 | The four cross-family helpers (`rand_ipv4`, `rand_ipv6`, `start_nlattr`, `build_nested_attrs`), widened from file-static so every per-group TU shares one body. |
| msg-rtnl-common.h | 66 | Private header for the above; included only by the msg-rtnl-* TUs. |
| rtnl-ack-oracle.h | 41 | The oracle's two-call contract: `rtnl_oracle_sample()` before the send, `rtnl_oracle_drain()` after it. |

## Subdirectories
- [genl/](genl/CLAUDE.md) — generic-netlink family grammars (47 files: 46 per-family + the runtime registry).
- [nfnl/](nfnl/CLAUDE.md) — netfilter-netlink subsystem grammars (12 files: 11 per-subsystem + the registry).

## Key invariants
- **Registry-of-tables, repeated.** genl families and nfnl subsystems share one shape: a small `{cmd, name}` + `{attr, kind, size}` table per unit, and a central registry (`genl/families.c`, `nfnl/subsystems.c`) resolves/dispatches by ID at runtime.
- **Attribute shapes are policy-mirrored** — sized/typed to match the kernel's own `nla_policy` so messages reach the real command parser instead of bouncing at `-EINVAL`. Comments name the kernel policy or validation gate an attribute shape targets.
- **genl family-id is dynamic** (resolved at runtime via `CTRL_CMD_GETFAMILY`); nfnl subsystem id is a compile-time `NFNL_SUBSYS_*` constant — hence genl needs the runtime registry, nfnl's is simpler.
- **genl dump flag follows the cmd's handlers** — the same reply says which of a family's ops have a doit, a dumpit or both; `genl_family_rcv_msg()` routes on `NLM_F_DUMP` and rejects a request whose routed handler is missing, so a dumpit-only cmd is sent the dump bits and a doit-only cmd neither, while both-or-unknown cmds and the 1-in-10 pure-chaos flags words are left to the random pick.
- **genl requests mostly clear the genl core's header check** — for a cmd at or past the family's `resv_start_op` (every cmd when it is left 0), `genl_header_check()` rejects a nonzero `genlmsghdr.reserved` and any flag outside REQUEST/ACK/ECHO and the dump pair before it looks the op up. A genl message therefore draws `NLM_F_ATOMIC` and the NEW/DELETE modifiers one time in 8 rather than every time (older families skip the check, and handlers such as gtp's read them), and carries a nonzero reserved word only when it is a chaos message. Other protocols draw the modifiers every time.

## Interactions
- `netlink_gen_msg` is wired into `net/proto/netlink.c`'s `proto_netlink`.
- Grammars are wired by extern struct (`fam_*`, subsystem grammars), consumed by the message generator.
- Conditional compilation: each genl family's `extern`/registry entry is gated by `__has_include()` against kernel UAPI headers, so coverage degrades gracefully on older kernels.
