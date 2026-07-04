# net/proto/ — Per-Address-Family Protocol Helpers

One file per `PF_*`/`AF_*` family. Each defines `const struct netproto proto_<family>` (the per-syscall hook table wired into `net/protocols.c`'s `net_protocols[]`) and, for families with coherent multi-call sequences, a `grammar_<family>` registered in `net/socket-family-grammar.c`'s `sfg_registry[]`. The socket core (protocols.c, sockaddr.c, socket-family-grammar.c, domains.c) stays in `net/`; this dir is the per-family *content* it dispatches to.

Shared pattern (`ip-udp.c`, 51 lines): build a `RAND_ARRAY` of valid optnames for the level/protocol, switch on the picked optname, size and fill `so->optval`/`so->optlen` per kernel expectation (including boundary values like GSO segment sizes 0/1/1400/65535).

## Files (42 files)

### Largest / notable
| File | Lines | Role |
|---|---|---|
| ipv4.c | 724 | Full AF_INET: raw sockets, IP options, ip_tables/ebtables/arp_tables/ip_set/ip_vs setsockopt levels, multicast. |
| ipv6.c | 559 | AF_INET6 equivalent. |
| ip-sctp.c | 538 | SCTP control surface. |
| llc.c / rxrpc.c / xdp.c | 478 / 469 / 454 | LLC SAP/link ops; RxRPC calls; AF_XDP umem/ring setup (via `xdp-umem-track.c`). |
| alg.c + alg-dict.c | 429 + 413 | AF_ALG crypto sockets; the dict is a curated table of real cipher/hash/AEAD names so `bind()` finds a registered transform instead of `-EINVAL`. |
| rds.c / packet.c / kcm.c / key.c | 398 / 335 / 349 / 323 | RDS; AF_PACKET; KCM (attaches a BPF classifier via `bpf.c`); PF_KEY. |
| netlink.c | 270 | `grammar_netlink`: membership churn + `SOL_NETLINK` toggles over GENERIC/ROUTE/NETFILTER/KOBJECT_UEVENT/AUDIT; delegates message-body shape to `netlink_gen_msg`. |

Plus ~25 smaller families under 160 lines following the same optname-table-plus-switch pattern (atm, x25, ib, icmp6, ip-{dccp,raw,tcp,udp,udplite}, iucv, nfc, phonet, smc, tipc, vsock, ieee802154, caif, mctp, mpls, can, bluetooth, pppox, qrtr, unix, ip-mptcp).

### XFRM (IPsec netlink) cluster
`grammar_xfrm` is the second AF_NETLINK grammar slot alongside `netlink.c`'s `grammar_netlink`, pinned to NETLINK_XFRM — a per-family grammar, so it lives here, not in `net/netlink/` (which holds the genl/nfnl message-table machinery).

| File | Lines | Role |
|---|---|---|
| netlink-xfrm-emit.c | 924 | One `xfrm_emit_*` per XFRM_MSG_* kind, each building a coherent attribute set (AEAD vs paired CRYPT+AUTH_TRUNC, optional COMP/ENCAP/REPLAY/ESN/marks). |
| netlink-xfrm.c | 642 | `grammar_xfrm`: the coherent NEWSA/UPDSA/NEWAE/EXPIRE/DELSA/NEWPOLICY/DELPOLICY/FLUSH* walk. |
| netlink-xfrm-attr.c | 414 | Attribute-building helpers shared by the emit functions. |
| netlink-xfrm-ring.c | 177 | Per-process installed-SA/policy ring so later UPDSA/DELSA/NEWAE target a real entry instead of an SPI the kernel rejects on lookup. |

## Key invariants
- **Two dispatch tables, both rooted in `net/`.** `net_protocols[]` (per-syscall hooks) and `sfg_registry[]` (coherent multi-call grammars) live in `net/`; a family can populate either, both, or neither. Every file here is an entry in one or both — linked by extern symbol, not by path, so relocation is link-safe.
- **Attribute shapes are policy-mirrored, not random.** optname/attr tables are sized and typed to match the kernel's own `nla_policy`, so messages reach the real parser instead of bouncing at `-EINVAL`.
- **XFRM ring must stay in sync** with what the kernel accepted — `netlink-xfrm-ring.c` only records entries `xfrm_emit_*` believed succeeded; a missed error path leaves stale entries referenced by later UPDSA/DELSA calls.
- **Wide conditional-compilation surface** — `USE_IPV6/RDS/BLUETOOTH/CAIF/VSOCK/XDP/MCTP/IF_ALG` gate whole families; a build exercises only the subset the target kernel supports.

## Interactions
- Contract is `include/net.h` — `struct netproto` plus the `extern const struct netproto proto_*` declarations every file here implements.
- Registered in `net/protocols.c` (`net_protocols[]`) and `net/socket-family-grammar.c` (`sfg_registry[]`); parity between the two tables is gated by `scripts/check-static/net-proto-sfg-parity.sh`.
- Consumed by `syscalls/socket.c` (`gen_socket_args`), `syscalls/setsockopt.c` (`do_setsockopt`), and `fds/sockets.c`; message bodies delegate to the netlink message machinery (`net/netlink/msg.c`).
