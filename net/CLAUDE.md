# net/ — Network Protocol & Netlink Fuzzing Surface

Generates sockaddr structures, setsockopt payloads, protocol-specific
message bodies, and BPF/eBPF programs for every address family and
netlink subsystem Trinity knows about. This is the largest subsystem
in the tree by file count.

## Files

Grouped by theme rather than enumerated — the long tail is highly
repetitive (one file per protocol/family/subsystem, following a
shared struct-of-callbacks pattern).

### Core dispatch/registry (small, load first to understand the rest)
- `protocols.c` — `net_protocols[TRINITY_PF_MAX]` — the master
  `PF_* -> struct netproto` table. `struct netproto` — every
  per-protocol file below populates one of these and is wired in here.
- `sockaddr.c` — `generate_sockaddr()`: picks a family (or honors
  `--domain`), looks up `net_protocols[pf]`, and calls its
  `gen_sockaddr` hook; falls back to a random blob for unregistered
  families. 50/50 chance it just emits `AF_UNSPEC` instead.
- `domains.c` — name<->`PF_*` lookup table for `--domain`
  and `--no_domain` CLI parsing (`find_specific_domain`,
  `parse_exclude_domains`).

### Per-address-family protocol helpers (`proto/`)

- [proto/](proto/CLAUDE.md) — the per-`PF_*`/`AF_*` files, each defining `const struct netproto proto_<family>` (wired into `net_protocols[]`). One family per file, shared optname-table-plus-switch pattern.

### Netlink message machinery (`netlink/`)

- [netlink/](netlink/CLAUDE.md) — the netlink message-construction engine (nlmsg framing, rtnetlink payloads) plus the genl-family and nfnl-subsystem grammar registries. Subdirs: [netlink/genl/](netlink/genl/CLAUDE.md) and [netlink/nfnl/](netlink/nfnl/CLAUDE.md). The AF_NETLINK *socket* helpers live in `proto/netlink.c`; this dir builds the *message bodies* they carry.

### BPF / eBPF program generation

- [bpf/](bpf/CLAUDE.md) — two independent BPF program generators (classic `sock_filter` for socket filters/seccomp, and tiered eBPF for `BPF_PROG_LOAD`), the classic-BPF disassembler, and the AF_XDP umem tracker.

## Key design decisions

2. **Registry-of-tables pattern repeated at 3 layers.** Address
   families (`net_protocols[]`), generic-netlink families
   (`netlink/genl/`), and
   netfilter-netlink subsystems (`netlink/nfnl/`) all use the same shape: a small header file
   declares `{cmd, name}` and `{attr, kind, size}` tables per unit,
   and a central file resolves/dispatches by ID at runtime.
3. **Attribute shapes are policy-mirrored, not random.** Per-family/
   per-subsystem `nla_attr_spec`/similar tables are sized and typed to
   match the kernel's own `nla_policy` tables exactly (comments cite
   the kernel source function), so generated messages pass the
   attribute-policy gate and reach the command's real parser instead
   of bouncing off `-EINVAL` at the TLV-validation layer.
4. **Conditional compilation keyed on target kernel headers.**
   `__has_include(<linux/X.h>)` gates each genl family's `extern`
   declaration and registry entry (netlink/genl/families.c), and
   `USE_*` build flags gate whole protocol families in
   `net_protocols[]` (IPV6, RDS, BLUETOOTH, VSOCK,
   XDP, MCTP, IF_ALG) — the directory compiles down to whatever
   subset the build/kernel config supports.

## Integration points

- `include/net.h` — declares `struct netproto`, `struct protoptr`,
  `net_protocols[]`, and every per-family `extern const struct
  netproto proto_*` — the contract every `net/proto/*.c` file implements.
- `syscalls/socket/socket.c` — `rand_proto_type()` and `gen_socket_args()`
  (despite being declared in net.h) are defined here, not in net/;
  they index `net_protocols[]` to pick a protocol/type consistent with
  the chosen family.
- `syscalls/socket/setsockopt.c` — `do_setsockopt()` is defined here; looks up
  `net_protocols[triplet->family].proto->setsockopt` and calls it,
  managing optval alloc/free lifecycle.
- `fds/sockets.c` — the main consumer: opens sockets, calls
  `generate_sockaddr()` for bind/connect targets, indexes
  `net_protocols[]` directly for privileged-triplet checks and to skip
  families the running kernel can't open (defends against OOB reads
  past `TRINITY_PF_MAX` with an explicit bounds comment).
- `struct_catalog/sockaddr-af.c`, `sockaddr-mcast.c`,
  `sockaddr-sockopt.c` — own the `sockaddr_storage` tagged-union
  per-AF field tables and setsockopt optval struct shapes (linger,
  packet_mreq, group_req, ip_mreqn, etc.) consumed by the generic
  struct-fill machinery; net/ itself has no `struct_catalog`
  references — sockaddr/optval *scalar* generation lives in net/,
  *struct-shaped* optval generation lives in struct_catalog/.
- `syscalls/bpf-prog.c`, `syscalls/process/seccomp.c`,
  `syscalls/socket/setsockopt.c`, `struct_catalog/bpf-prog.c`,
  `args/struct_fill.c` — the consumers of the classic-BPF/eBPF generators
  (bpf/bpf.c + the bpf/ebpf*.c cluster), by symbol: filter programs
  attach via seccomp, `SO_ATTACH_FILTER` and `BPF_PROG_LOAD`.

## Areas of attention

2. **The eBPF generator's three tiers are three TUs** —
   `bpf/ebpf.c` (120) holds the fill-into-buffer core and the tier
   pick; valid-program synthesis (`ebpf-tier1.c`), boundary-case
   synthesis (`ebpf-tier2.c`) and pure-chaos corruption
   (`ebpf-tier3.c`) are separate files, but they share
   `ebpf-helpers.c` / `ebpf-regs.c` / `ebpf-map-fd.c`, so a change to a
   shared emitter reaches all three tiers at once.
