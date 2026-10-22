# net/proto/ — Per-Address-Family Protocol Helpers

One file per `PF_*`/`AF_*` family. Each defines `const struct netproto proto_<family>` (the per-syscall hook table wired into `net/protocols.c`'s `net_protocols[]`) and, for families with coherent multi-call sequences, a `grammar_<family>` registered in `net/socket-family-grammar-core.c`'s `sfg_registry[]`. The socket core (protocols.c, sockaddr.c, the socket-family-grammar-*.c cluster, domains.c) stays in `net/`; this dir is the per-family *content* it dispatches to.

Shared pattern (`ip-udp.c`, 50 lines): build a `RAND_ARRAY` of valid optnames for the level/protocol, switch on the picked optname, size and fill `so->optval`/`so->optlen` per kernel expectation (including boundary values like GSO segment sizes 0/1/1400/65535).

## Files (37 .c files, ~9,671 LOC)

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

## Key invariants
- **Two dispatch tables, both rooted in `net/`.** `net_protocols[]` (per-syscall hooks) and `sfg_registry[]` (coherent multi-call grammars) live in `net/`; a family can populate either, both, or neither. Every file here is an entry in one or both — linked by extern symbol, not by path, so relocation is link-safe.
- **Attribute shapes are policy-mirrored, not random.** optname/attr tables are sized and typed to match the kernel's own `nla_policy`, so messages reach the real parser instead of bouncing at `-EINVAL`.
- **Wide conditional-compilation surface** — `USE_IPV6/RDS/BLUETOOTH/VSOCK/XDP/MCTP/IF_ALG` gate whole families; a build exercises only the subset the target kernel supports.

## Interactions
- Contract is `include/net.h` — `struct netproto` plus the `extern const struct netproto proto_*` declarations every file here implements.
- Registered in `net/protocols.c` (`net_protocols[]`) and `net/socket-family-grammar-core.c` (`sfg_registry[]`); parity between the two tables is gated by `scripts/check-static/net-proto-sfg-parity.sh`.
- Consumed by `syscalls/socket/socket.c` (`gen_socket_args`), `syscalls/socket/setsockopt.c` (`do_setsockopt`), and `fds/sockets.c`; message bodies delegate to the netlink message machinery (`net/netlink/msg-core.c`).
