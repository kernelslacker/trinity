# net/proto/ — Per-Address-Family Protocol Helpers

One file per `PF_*`/`AF_*` family. Each defines `const struct netproto proto_<family>`, the per-syscall hook table wired into `net/protocols.c`'s `net_protocols[]`. The socket core (protocols.c, sockaddr.c, domains.c) stays in `net/`; this dir is the per-family *content* it dispatches to.

Shared pattern (`ip-udp.c`, 50 lines): build a `RAND_ARRAY` of valid optnames for the level/protocol, switch on the picked optname, size and fill `so->optval`/`so->optlen` per kernel expectation (including boundary values like GSO segment sizes 0/1/1400/65535).

## Files (37 .c files, ~5,693 LOC)

### Largest / notable
| File | Lines | Role |
|---|---|---|
| ip-sctp.c | 538 | SCTP control surface. |
| ipv4.c | 522 | Full AF_INET: raw sockets, IP options, ip_tables/ebtables/arp_tables/ip_set/ip_vs setsockopt levels, multicast. |
| alg.c + alg-dict.c | 435 + 414 | AF_ALG crypto sockets; the dict is a curated table of real cipher/hash/AEAD names so `bind()` finds a registered transform instead of `-EINVAL`. |
| ipv6.c | 380 | AF_INET6 equivalent of ipv4.c. |
| key.c | 350 | PF_KEY. |
| xdp.c | 251 | AF_XDP umem/ring setup (via `net/bpf/xdp-umem-track.c`). |
| packet.c / netlink.c | 172 / 133 | AF_PACKET; AF_NETLINK per-protocol sockaddr and `SOL_NETLINK` options, delegating message-body shape to `netlink_gen_msg` and draining the rtnl ACK oracle in `post_send`. |

Plus the remaining families following the same optname-table-plus-switch pattern: pppox (244), can (238), bluetooth (236), ip-tcp (169), unix (102), llc (100), tipc (98), vsock (90), phonet (88), rds (87), rxrpc (84), ip-mptcp (83), iucv (82), nfc (75), ieee802154 (71), ip-udplite (68), atm (64), smc (59), ip-dccp (57), icmp6 (51), ip-udp (50), ib (50), kcm (47), x25 (45), mctp (45), ip-raw (44), mpls (40), qrtr (31).

## Key invariants
- **One dispatch table, rooted in `net/`.** `net_protocols[]` (per-syscall hooks) lives in `net/`; every file here is an entry in it, linked by extern symbol, not by path, so relocation is link-safe.
- **Attribute shapes are policy-mirrored, not random.** optname/attr tables are sized and typed to match the kernel's own `nla_policy`, so messages reach the real parser instead of bouncing at `-EINVAL`.
- **Wide conditional-compilation surface** — `USE_IPV6/RDS/BLUETOOTH/VSOCK/XDP/MCTP/IF_ALG` gate whole families; a build exercises only the subset the target kernel supports.

## Interactions
- Contract is `include/net.h` — `struct netproto` plus the `extern const struct netproto proto_*` declarations every file here implements.
- Registered in `net/protocols.c` (`net_protocols[]`).
- Consumed by `syscalls/socket/socket.c` (`gen_socket_args`), `syscalls/socket/setsockopt.c` (`do_setsockopt`), and `fds/sockets.c`; message bodies delegate to the netlink message machinery (`net/netlink/msg-core.c`).
