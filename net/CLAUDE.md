# net/ — Network Protocol & Netlink Fuzzing Surface

Generates sockaddr structures, setsockopt payloads, protocol-specific
message bodies, and BPF/eBPF programs for every address family and
netlink subsystem Trinity knows about. This is the largest subsystem
in the tree by file count.

## Files (123 .c files + 5 headers, ~22,324 LOC)

Grouped by theme rather than enumerated — the long tail is highly
repetitive (one file per protocol/family/subsystem, following a
shared struct-of-callbacks pattern).

### Core dispatch/registry (small, load first to understand the rest)
- `protocols.c` (50) — `net_protocols[TRINITY_PF_MAX]` — the master
  `PF_* -> struct netproto` table. `struct netproto` (defined in
  `include/net.h`) is `{name, valid_triplets, socket_setup,
  setsockopt, gen_sockaddr, gen_msg, nr_triplets, ...}` — every
  per-protocol file below populates one of these and is wired in here.
- `sockaddr.c` (47) — `generate_sockaddr()`: picks a family (or honors
  `--specific-domain`), looks up `net_protocols[pf]`, and calls its
  `gen_sockaddr` hook; falls back to a random blob for unregistered
  families. 50/50 chance it just emits `AF_UNSPEC` instead.
- `domains.c` (157) — name<->`PF_*` lookup table for `--specific-domain`
  and `--exclude-domains` CLI parsing (`find_specific_domain`,
  `parse_exclude_domains`).

### Per-address-family protocol helpers (`proto/`)

- [proto/](proto/CLAUDE.md) — the 37 per-`PF_*`/`AF_*` files, each defining `const struct netproto proto_<family>` (wired into `net_protocols[]`). One family per file, shared optname-table-plus-switch pattern.

### Netlink message machinery (`netlink/`)

- [netlink/](netlink/CLAUDE.md) — the netlink message-construction engine (nlmsg framing, rtnetlink payloads) plus the genl-family and nfnl-subsystem grammar registries. Subdirs: [netlink/genl/](netlink/genl/CLAUDE.md) (47 files) and [netlink/nfnl/](netlink/nfnl/CLAUDE.md) (12). The AF_NETLINK *socket* helpers live in `proto/netlink.c`; this dir builds the *message bodies* they carry.

### BPF / eBPF program generation

- [bpf/](bpf/CLAUDE.md) — two independent BPF program generators (classic `sock_filter` for socket filters/seccomp, and tiered eBPF for `BPF_PROG_LOAD`), the classic-BPF disassembler, and the AF_XDP umem tracker (10 `.c` files + 2 internal headers). The eBPF side is split one tier per TU behind `ebpf-internal.h`: `ebpf.c` (126) keeps only the fill-into-buffer core and tier pick, with `ebpf-tier1.c` (404), `ebpf-tier2.c` (244), `ebpf-tier3.c` (164) and the shared `ebpf-helpers.c` (207) / `ebpf-regs.c` (85) / `ebpf-map-fd.c` (80).

### Misc
- `unblocker.c` (310) — loopback-only accept-unblocker / pipe-waker
  connector helpers (fire-and-forget, bounded work, cannot wedge the
  caller); used to stop other children's blocking `accept()`/`recv()`
  calls from stalling the fuzzer.

## Key design decisions

1. **One per-family hook table.** `net_protocols[]` (protocols.c) holds
   each family's per-syscall hooks (sockaddr, setsockopt, one-shot
   message body); `generate_sockaddr()` falls back to a random blob
   for a family with no entry.
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
5. **BPF has two independent, uncoupled generators.** Classic BPF
   (bpf/bpf.c, cBPF `sock_filter`) targets socket filters/seccomp; eBPF
   (the `bpf/ebpf*.c` cluster) targets `BPF_PROG_LOAD` and is tiered
   (valid/boundary/chaos) to separately stress the verifier's
   acceptance path and its rejection path. They share no code — each
   side has its own private header: `bpf/internal.h` is included only
   by `bpf/bpf.c` and `bpf/disasm.c`, `bpf/ebpf-internal.h` only by the
   eBPF cluster.
6. **Deliberate policy-driven attribute coverage.** Several genl family
   files (e.g. taskstats) name the kernel policy or validation function
   in a header comment and size their attribute tables to reach exactly
   that code path.

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

1. **The netlink message generator has been split twice** — first the
   rtnl payloads out of the message generator, then each rtnl group out
   of the payload file. `netlink/msg-rtnl-neigh.c` (905) is now the
   largest file here, followed by `netlink/msg-rtnl-tc.c` (607),
   `netlink/msg-tables.c` (590), `netlink/msg-rtnl-route.c` (578) and
   `netlink/msg-attr-random.c` (480). A single payload generator still
   spans hundreds of lines of nested attribute construction.
2. **The eBPF generator's three tiers are now three TUs** —
   `bpf/ebpf.c` (126) keeps only the fill-into-buffer core and the tier
   pick; valid-program synthesis (`ebpf-tier1.c`), boundary-case
   synthesis (`ebpf-tier2.c`) and pure-chaos corruption
   (`ebpf-tier3.c`) no longer sit side by side, but they still share
   `ebpf-helpers.c` / `ebpf-regs.c` / `ebpf-map-fd.c`, so a change to a
   shared emitter reaches all three tiers at once.
3. **`net_protocols[]` sizing** — `fds/sockets.c` carries an explicit
   bounds-safety comment about indexing `net_protocols[]` past
   `TRINITY_PF_MAX`, which flags this class of risk directly.
4. **Conditional compilation surface is wide**: `USE_IPV6`, `USE_RDS`,
   `USE_BLUETOOTH`, `USE_VSOCK`, `USE_XDP`, `USE_MCTP`,
   `USE_IF_ALG`, plus per-genl-family `__has_include()` checks — a
   given build only exercises the subset the target kernel headers and
   build flags allow, so coverage silently shrinks on older kernels.

## Summary

net/ is a large, mechanically uniform collection of per-protocol and
per-netlink-family "grammar" tables (command IDs + attribute specs
mirroring kernel `nla_policy`) plumbed through three parallel
registry-and-dispatch layers (address family, genl family, nfnl
subsystem), plus two independent BPF program generators and the core
netlink message-construction engine. Complexity concentrates in a
handful of files — the rtnl payload builders, the main netlink message
generator, and the eBPF tiers — while the other
~100 files are short, self-similar, one-family-per-file grammar
definitions that are cheap to read individually and cheap to extend
by copying an existing sibling.
