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

### Generic netlink (genl) family grammars
- `netlink-genl-families.c` (621) — runtime registry: walks
  statically-declared `genl_family_grammar` structs, resolves each
  family's dynamic `family_id` via `CTRL_CMD_GETFAMILY`/`NLM_F_DUMP`,
  exposes lookup helpers to the message generator. Families are
  conditionally compiled via `__has_include()` against kernel UAPI
  headers so the build degrades gracefully on older kernels.
- `netlink-genl-fam-*.c` — 45 files, one per genl family (nl80211,
  ethtool, devlink, wireguard, macsec, nfsd, ovs, tipc, dpll,
  psp, handshake, netlabel, thermal, ...). Pattern shown by
  `netlink-genl-fam-taskstats.c` (54 lines, smallest): a
  `genl_cmd_grammar[]` table of `{CMD, "name"}`, an
  `nla_attr_spec[]` table of `{ATTR, NLA_KIND_*, size}` mirroring the
  kernel's `nla_policy`, packaged into one `struct genl_family_grammar`.
  Comments frequently cite the specific CVE or kernel validation gate
  the attribute shape is designed to reach (e.g. taskstats file cites
  CVE-2017-2671). Largest: `netlink-genl-fam-ovs.c` (441),
  `netlink-genl-fam-macsec.c` (232), `netlink-genl-fam-netlabel.c` (226),
  `netlink-genl-fam-nl802154.c` (209), `netlink-genl-fam-ieee802154.c` (201).
  ~35 files are under 130 lines, following the taskstats pattern exactly.

### Netfilter netlink (nfnl) subsystem grammars
- `netlink-nfnl-subsystems.c` (160) — per-subsystem registry, analogous
  to the genl one but simpler: `NFNL_SUBSYS_*` is a compile-time
  constant (no dynamic family-id resolution needed), so this file just
  stamps each grammar's stats counter into the shared arena.
- `netlink-nfnl-sub-*.c` — 11 files (ipset, nftables, nft-compat,
  ctnetlink, cttimeout, cthelper, nfqueue, acct, osf, ulog, hook),
  same `{cmd, attrs}` table pattern as genl files, 59-127 lines each.

### Core netlink message plumbing
- `netlink-msg.c` (1757) — second-largest file: `netlink_gen_msg()`
  (the `gen_msg` hook wired into `proto_netlink`), nlmsg flag/type
  generation, dispatches to per-rtnetlink-group payload builders and
  the genl/nfnl grammars, occasional deliberate corruption of
  otherwise-valid messages.
- `netlink-msg-rtnl-payloads.c` (2283) — largest file in the directory:
  five payload generators (`gen_rta_{route,link,addr,neigh,dcb}_payload`)
  split out of netlink-msg.c purely for compile-unit size/parallelism;
  dispatched from a switch in netlink-msg.c. File-static helpers
  (`rand_ipv4`, `rand_ipv6`, `start_nlattr`, `build_nested_attrs`) are
  shared only within this TU.
- `netlink-msg-tables.c` (386) — shared lookup/size tables consumed by
  both of the above.
- `netlink-msg-internal.h` (169) — private cross-TU declarations
  binding the three files above together (explicitly not for outside
  inclusion).

### BPF / eBPF program generation
- `bpf.c` (554) — classic BPF (`struct sock_filter`) program generator
  for socket filters (`SO_ATTACH_FILTER`) and seccomp; builds
  instruction sequences, invokes the disassembler at high verbosity
  for debug output.
- `bpf-disasm.c` (447) — classic BPF disassembler, used only for debug
  logging of what `bpf.c` generated (`bpf_disasm_all`).
- `bpf-internal.h` (153) — private shared declarations + opcode-bit
  fallback macros for the bpf.c/bpf-disasm.c pair only.
- `ebpf.c` (1266) — third-largest file: independent eBPF generator
  (BPF_PROG_LOAD-style programs) with three explicit tiers: Tier 1
  verifier-valid programs (forward jumps, liveness, bounded stack,
  valid helper calls), Tier 2 boundary/edge-case programs (near-limit
  complexity, unchecked map lookups, ALU overflow), Tier 3 chaos
  (invalid opcodes, backward jumps, OOB registers, malformed 128-bit
  loads) — targets the verifier and JIT directly.

### Misc
- `unblocker.c` (309) — loopback-only accept-unblocker / pipe-waker
  connector helpers (fire-and-forget, bounded work, cannot wedge the
  caller); used to stop other children's blocking `accept()`/`recv()`
  calls from stalling the fuzzer.
- `xdp-umem-track.c` (95) — fixed 256-slot table tracking AF_XDP umem
  fd/ptr/len triples; used by `proto-xdp.c`.

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
