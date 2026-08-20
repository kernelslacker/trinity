# net/proto/ — Per-Address-Family Protocol Helpers

One file per `PF_*`/`AF_*` family. Each defines `const struct netproto proto_<family>` (the per-syscall hook table wired into `net/protocols.c`'s `net_protocols[]`) and, for families with coherent multi-call sequences, a `grammar_<family>` registered in `net/socket-family-grammar-core.c`'s `sfg_registry[]`. The socket core (protocols.c, sockaddr.c, the socket-family-grammar-*.c cluster, domains.c) stays in `net/`; this dir is the per-family *content* it dispatches to.

Shared pattern (`ip-udp.c`, 50 lines): build a `RAND_ARRAY` of valid optnames for the level/protocol, switch on the picked optname, size and fill `so->optval`/`so->optlen` per kernel expectation (including boundary values like GSO segment sizes 0/1/1400/65535).

## Files (43 .c files, ~12,089 LOC)

### Largest / notable
| File | Lines | Role |
|---|---|---|
| ipv4.c | 780 | Full AF_INET: raw sockets, IP options, ip_tables/ebtables/arp_tables/ip_set/ip_vs setsockopt levels, multicast. |
| rds.c | 667 | RDS. |
| ipv6.c | 618 | AF_INET6 equivalent of ipv4.c. |
| alg.c + alg-dict.c | 539 + 414 | AF_ALG crypto sockets; the dict is a curated table of real cipher/hash/AEAD names so `bind()` finds a registered transform instead of `-EINVAL`. |
| ip-sctp.c | 538 | SCTP control surface. |
| llc.c / rxrpc.c / xdp.c | 478 / 470 / 455 | LLC SAP/link ops; RxRPC calls; AF_XDP umem/ring setup (via `net/bpf/xdp-umem-track.c`). |
| key.c / kcm.c / unix.c / packet.c | 350 / 349 / 342 / 334 | PF_KEY; KCM (attaches a BPF classifier via `net/bpf/bpf.c`); AF_UNIX; AF_PACKET. |
| netlink.c | 285 | `grammar_netlink`: membership churn + `SOL_NETLINK` toggles over GENERIC/ROUTE/NETFILTER/KOBJECT_UEVENT/AUDIT; delegates message-body shape to `netlink_gen_msg`. |

Plus the remaining families following the same optname-table-plus-switch pattern: mctp (290), mpls (285), ip-mptcp (285), bluetooth (253), can (247), pppox (244), qrtr (235), ip-tcp (169), tipc (107), vsock (99), phonet (97), iucv (82), nfc (75), ieee802154 (71), smc (68), ip-udplite (68), atm (64), ip-dccp (57), icmp6 (51), ip-udp (50), ib (50), x25 (45), ip-raw (44).

### XFRM (IPsec netlink) cluster
`grammar_xfrm` is the second AF_NETLINK grammar slot alongside `netlink.c`'s `grammar_netlink`, pinned to NETLINK_XFRM — a per-family grammar, so it lives here, not in `net/netlink/` (which holds the genl/nfnl message-table machinery). The `xfrm_emit_*` builders were carved by message family into three TUs, all sharing `include/proto-netlink-xfrm-internal.h`.

| File | Lines | Role |
|---|---|---|
| netlink-xfrm-state.c | 680 | The SA-family `xfrm_emit_*` builders (newsa, allocspi, updsa, newae, delsa_random, expire, migrate_state), each building a coherent attribute set (AEAD vs paired CRYPT+AUTH_TRUNC, optional COMP/ENCAP/REPLAY/ESN/marks). |
| netlink-xfrm.c | 571 | `grammar_xfrm`: the coherent NEWSA/UPDSA/NEWAE/EXPIRE/DELSA/NEWPOLICY/DELPOLICY/FLUSH* walk. |
| netlink-xfrm-attr.c | 501 | Attribute appenders, algorithm-name rotation tables, and address / selector / lifetime helpers shared by the emit TUs. |
| netlink-xfrm-policy.c | 325 | The policy-family `xfrm_emit_*` builders (newpolicy, delpolicy, polexpire, migrate, setdefault, getdefault). |
| netlink-xfrm-misc.c | 180 | Everything left over after the state and policy carves: `xfrm_emit_acquire`, `xfrm_emit_flushsa`, `xfrm_emit_flushpolicy`. |
| netlink-xfrm-ring.c | 177 | Per-process installed-SA/policy rings so later UPDSA/DELSA/NEWAE target a real entry instead of an SPI the kernel rejects on lookup. |

## Key invariants
- **Two dispatch tables, both rooted in `net/`.** `net_protocols[]` (per-syscall hooks) and `sfg_registry[]` (coherent multi-call grammars) live in `net/`; a family can populate either, both, or neither. Every file here is an entry in one or both — linked by extern symbol, not by path, so relocation is link-safe.
- **Attribute shapes are policy-mirrored, not random.** optname/attr tables are sized and typed to match the kernel's own `nla_policy`, so messages reach the real parser instead of bouncing at `-EINVAL`.
- **XFRM ring must stay in sync** with what the kernel accepted — `netlink-xfrm-ring.c` only records entries `xfrm_emit_*` believed succeeded; a missed error path leaves stale entries referenced by later UPDSA/DELSA calls.
- **Wide conditional-compilation surface** — `USE_IPV6/RDS/BLUETOOTH/VSOCK/XDP/MCTP/IF_ALG` gate whole families; a build exercises only the subset the target kernel supports.

## Interactions
- Contract is `include/net.h` — `struct netproto` plus the `extern const struct netproto proto_*` declarations every file here implements.
- Registered in `net/protocols.c` (`net_protocols[]`) and `net/socket-family-grammar-core.c` (`sfg_registry[]`); parity between the two tables is gated by `scripts/check-static/net-proto-sfg-parity.sh`.
- Consumed by `syscalls/socket/socket.c` (`gen_socket_args`), `syscalls/socket/setsockopt.c` (`do_setsockopt`), and `fds/sockets.c`; message bodies delegate to the netlink message machinery (`net/netlink/msg-core.c`).
