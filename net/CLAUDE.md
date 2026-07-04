# net/ — Network Protocol & Netlink Fuzzing Surface

Generates sockaddr structures, setsockopt payloads, protocol-specific
message bodies, and BPF/eBPF programs for every address family and
netlink subsystem Trinity knows about. This is the largest subsystem
in the tree by file count.

## Files (114 files, ~26,684 LOC)

Grouped by theme rather than enumerated — the long tail is highly
repetitive (one file per protocol/family/subsystem, following a
shared struct-of-callbacks pattern).

### Core dispatch/registry (small, load first to understand the rest)
- `protocols.c` (53) — `net_protocols[TRINITY_PF_MAX]` — the master
  `PF_* -> struct netproto` table. `struct netproto` (defined in
  `include/net.h`) is `{name, valid_triplets, socket_setup,
  setsockopt, gen_sockaddr, gen_msg, nr_triplets, ...}` — every
  per-protocol file below populates one of these and is wired in here.
- `sockaddr.c` (45) — `generate_sockaddr()`: picks a family (or honors
  `--specific-domain`), looks up `net_protocols[pf]`, and calls its
  `gen_sockaddr` hook; falls back to a random blob for unregistered
  families. 50/50 chance it just emits `AF_UNSPEC` instead.
- `domains.c` (158) — name<->`PF_*` lookup table for `--specific-domain`
  and `--exclude-domains` CLI parsing (`find_specific_domain`,
  `parse_exclude_domains`).
- `socket-family-grammar.c` (366) — `sfg_registry[]`, a second,
  independent dispatch table (`struct socket_family_grammar`) driving
  coherent multi-call sequences (setsockopt -> bind -> listen ->
  accept -> sendmsg) per family, one entry per `net/proto/<family>.c`.
  Falls back to the legacy v1 `run_alg_chain` path when a family has
  no grammar registered. Each protocol file that defines a grammar
  (`grammar_inet`, `grammar_unix`, `grammar_xfrm`, etc.) is declared
  extern and listed here.

### Per-address-family protocol helpers (`proto/`)

- [proto/](proto/CLAUDE.md) — the 42 per-`PF_*`/`AF_*` files, each defining `const struct netproto proto_<family>` (wired into `net_protocols[]`) plus optional `grammar_<family>` (registered in `sfg_registry[]`), including the XFRM (IPsec netlink) grammar cluster. One family per file, shared optname-table-plus-switch pattern.

### Netlink message machinery (`netlink/`)

- [netlink/](netlink/CLAUDE.md) — the netlink message-construction engine (nlmsg framing, rtnetlink payloads) plus the genl-family and nfnl-subsystem grammar registries. Subdirs: [netlink/genl/](netlink/genl/CLAUDE.md) (46 files) and [netlink/nfnl/](netlink/nfnl/CLAUDE.md) (12). The AF_NETLINK *socket* helpers (`grammar_netlink`, `grammar_xfrm`) live in `proto/`; this dir builds the *message bodies* they carry.

### BPF / eBPF program generation

- [bpf/](bpf/CLAUDE.md) — two independent BPF program generators (classic `sock_filter` for socket filters/seccomp, and tiered eBPF for `BPF_PROG_LOAD`), the classic-BPF disassembler, and the AF_XDP umem tracker (4 files + internal header).

### Misc
- `unblocker.c` (309) — loopback-only accept-unblocker / pipe-waker
  connector helpers (fire-and-forget, bounded work, cannot wedge the
  caller); used to stop other children's blocking `accept()`/`recv()`
  calls from stalling the fuzzer.

## Key design decisions

1. **Two independent per-family dispatch tables.** `net_protocols[]`
   (protocols.c) is the original per-syscall hook table (sockaddr,
   setsockopt, one-shot message body). `sfg_registry[]`
   (socket-family-grammar.c) is a newer, opt-in table for *coherent
   multi-call sequences* per family (bind -> listen -> accept ->
   sendmsg with matching state). A family can have either, both, or
   neither; grammars are added incrementally without touching the
   older table.
2. **Registry-of-tables pattern repeated at 3 layers.** Address
   families (`net_protocols[]`), generic-netlink families
   (`netlink-genl-families.c` + `netlink-genl-fam-*.c`), and
   netfilter-netlink subsystems (`netlink-nfnl-subsystems.c` +
   `netlink-nfnl-sub-*.c`) all use the same shape: a small header file
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
   declaration and registry entry (netlink-genl-families.c), and
   `USE_*` build flags gate whole protocol families in
   `net_protocols[]`/`sfg_registry[]` (IPV6, RDS, BLUETOOTH, CAIF,
   VSOCK, XDP, MCTP, IF_ALG) — the directory compiles down to whatever
   subset the build/kernel config supports.
5. **Stateful sequencing via rings.** XFRM keeps a per-process ring of
   installed SAs/policies (proto-netlink-xfrm-ring.c) so later
   UPDSA/NEWAE/DELSA calls target real kernel objects instead of
   random SPIs that fail lookup — the same "install then reference"
   idea recurs informally in other coherent-grammar files.
6. **BPF has two independent, uncoupled generators.** Classic BPF
   (bpf.c, cBPF `sock_filter`) targets socket filters/seccomp; eBPF
   (ebpf.c) targets `BPF_PROG_LOAD` and is tiered (valid/boundary/
   chaos) to separately stress the verifier's acceptance path and its
   rejection path. They share no code — bpf-internal.h is explicitly
   private to the bpf.c/bpf-disasm.c pair only.
7. **Deliberate CVE-driven attribute coverage.** Several genl family
   files (e.g. taskstats) document a specific historical CVE or kernel
   validation function in a header comment and size their attribute
   tables to reach exactly that code path.

## Integration points

- `include/net.h` — declares `struct netproto`, `struct protoptr`,
  `net_protocols[]`, and every per-family `extern const struct
  netproto proto_*` — the contract every proto-*.c file implements.
- `syscalls/socket.c` — `rand_proto_type()` and `gen_socket_args()`
  (despite being declared in net.h) are defined here, not in net/;
  they index `net_protocols[]` to pick a protocol/type consistent with
  the chosen family.
- `syscalls/setsockopt.c` — `do_setsockopt()` is defined here; looks up
  `net_protocols[triplet->family].proto->setsockopt` and calls it,
  managing optval alloc/free lifecycle.
- `fds/sockets.c` — the main consumer: opens sockets, calls
  `generate_sockaddr()` for bind/connect targets, indexes
  `net_protocols[]` directly for privileged-triplet checks and to skip
  families the running kernel can't open (defends against OOB reads
  past `TRINITY_PF_MAX` with an explicit bounds comment).
- `childops/socket-family-chain.c` — outer dispatcher for
  `socket-family-grammar.c`'s `sfg_registry[]`; falls back to the
  legacy `run_alg_chain` v1 path when no grammar is registered for a
  family.
- `struct_catalog/sockaddr-af.c`, `sockaddr-mcast.c`,
  `sockaddr-sockopt.c` — own the `sockaddr_storage` tagged-union
  per-AF field tables and setsockopt optval struct shapes (linger,
  packet_mreq, group_req, ip_mreqn, etc.) consumed by the generic
  struct-fill machinery; net/ itself has no `struct_catalog`
  references — sockaddr/optval *scalar* generation lives in net/,
  *struct-shaped* optval generation lives in struct_catalog/.
- `childops/genetlink-fuzzer.c` — does its own independent runtime
  discovery of a family's ops list; intentionally decoupled from
  `netlink-genl-families.c`'s registry so the two paths can't share
  fragile state.
- `syscalls/bpf.c`, `syscalls/seccomp.c`, `syscalls/prctl.c`,
  `syscalls/setsockopt.c`, `syscalls/io_uring_register-payloads.c`,
  `childops/bpf-lifecycle.c`, `childops/bpf-cgroup-attach.c`,
  `childops/sock-ulp-sockmap-layering.c`,
  `childops/veth-asymmetric-xdp.c`, `childops/afxdp-churn.c`,
  `fds/bpf.c`, `struct_catalog/bpf.c` — wide fan-out of consumers of
  the classic-BPF/eBPF generators (bpf.c/ebpf.c), since filter programs
  attach via seccomp, `SO_ATTACH_FILTER`, `BPF_PROG_LOAD`, sockmap, and
  cgroup/XDP attach points.
- `net/proto/kcm.c` — one of the few proto files that itself pulls in
  `bpf.c` output (KCM sockets can have a BPF classifier attached).

## Areas of attention

1. **`netlink-msg-rtnl-payloads.c` (2283 lines) and `netlink-msg.c`
   (1757 lines)** are by far the largest files here; both were already
   split once for compile-unit size (rtnl payloads carved out of the
   message generator) but each single payload generator
   (`gen_rta_{route,link,addr,neigh,dcb}_payload`) still spans hundreds
   of lines of nested attribute construction.
2. **`ebpf.c` (1266 lines) mixes concerns**: valid-program synthesis,
   boundary-case synthesis, and pure-chaos corruption all live in one
   TU across three explicit tiers — logic for "is this instruction
   selection still verifier-valid" and "deliberately break this" sit
   side by side.
3. **`net_protocols[]` and `sfg_registry[]` can silently diverge** —
   nothing enforces that a family present in one table is present (or
   absent) in the other; `fds/sockets.c` carries an explicit
   bounds-safety comment about `net_protocols[]` sizing that flags this
   class of risk directly.
4. **XFRM correctness depends on the SA/policy ring staying in sync**
   with what the kernel actually accepted — `proto-netlink-xfrm-ring.c`
   only records entries `xfrm_emit_*` believes succeeded; any missed
   error path leaves stale ring entries referenced by later
   UPDSA/DELSA calls.
5. **Conditional compilation surface is wide**: `USE_IPV6`, `USE_RDS`,
   `USE_BLUETOOTH`, `USE_CAIF`, `USE_VSOCK`, `USE_XDP`, `USE_MCTP`,
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
generator, the XFRM emit cluster, and ebpf.c — while the other ~90
files are short, self-similar, one-family-per-file grammar
definitions that are cheap to read individually and cheap to extend
by copying an existing sibling.
