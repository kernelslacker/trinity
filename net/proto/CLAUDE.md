# net/proto/ — Per-Address-Family Protocol Helpers

Shared pattern (`ip-udp.c`, 50 lines): build a `RAND_ARRAY` of valid optnames for the level/protocol, switch on the picked optname, size and fill `so->optval`/`so->optlen` per kernel expectation (including boundary values like GSO segment sizes 0/1/1400/65535).

## Files

### Largest / notable
| File | Role |
|---|---|
| ip-sctp.c | SCTP control surface. |
| ipv4.c | Full AF_INET: raw sockets, IP options, ip_tables/ebtables/arp_tables/ip_set/ip_vs setsockopt levels, multicast. |
| alg.c + alg-dict.c | AF_ALG crypto sockets; the dict is a curated table of real cipher/hash/AEAD names so `bind()` finds a registered transform instead of `-EINVAL`. |
| ipv6.c | AF_INET6 equivalent of ipv4.c. |
| key.c | PF_KEY. |
| xdp.c | AF_XDP umem/ring setup (via `net/bpf/xdp-umem-track.c`). |
| packet.c / netlink.c | AF_PACKET; AF_NETLINK per-protocol sockaddr and `SOL_NETLINK` options, delegating message-body shape to `netlink_gen_msg` and draining the rtnl ACK oracle in `post_send`. |

## Key invariants
- **One dispatch table, rooted in `net/`.** `net_protocols[]` (per-syscall hooks) lives in `net/`; every file here is an entry in it, linked by extern symbol, not by path, so relocation is link-safe.
