# childops/ — Scripted/stateful per-child fuzz workloads for Trinity

Trinity's default fuzzing loop (`random_syscall/`) picks one syscall in
isolation per iteration. Many kernel bug classes (UAF/refcount races,
teardown-vs-lookup races, multi-step object lifecycles) only surface when a
specific *sequence* of syscalls runs with real state threaded through it.
childops/ is where those scripted sequences live: each file implements one
"childop" — a self-contained C function, dispatched instead of a random
syscall for the current fork'd child, that drives a fixed or semi-fixed
sequence against one kernel subsystem/feature/race window.

237 `.c` files + 21 `.h` files, ~134,500 LOC total, grouped into
per-domain subdirectories: `net/` (103 `.c`, plus `net/netlink/` 14,
`net/netfilter/` 5 with a further 14 under `net/netfilter/nftables/`,
`net/xfrm/` 13, `net/tc/` 5), `misc/` (32), `mm/` (16), `fs/` (13),
`recipe/` (11), `io_uring/` (10), `process/` (1).

## Files

### Structural pattern

A typical childop file is one self-contained translation unit:

1. A long top-of-file comment block explaining *why* — which CVE class or
   kernel code path is targeted, why per-syscall random fuzzing can't reach
   it, and the exact syscall sequence being driven. This is the primary
   documentation of kernel-bug intent in the whole codebase; read it before
   the code.
2. `#include "child.h"`, `"shm.h"`, `"trinity.h"`, `"random.h"`/`"rnd.h"`
   nearly always; plus whichever protocol helper headers it needs
   (`childops-netlink.h`, `childops-genl.h`, `childops-nfnl.h`,
   `childops-iouring.h`, `userns-bootstrap.h`, `childops-util.h`).
3. Local `#define` bounds (`MAX_ROUNDS`, `MAX_FORKS`, budget-ns constants) —
   every childop is hard-capped so a wedge or storm can't starve the fleet;
   `alarm(1)` armed by child.c around every non-syscall op backstops any
   still-wedged path.
4. Static helpers, then one exported entry point matching
   `bool <name>(struct childdata *child)` — the name matches the
   `enum child_op_type` case in `child-altop-table.c` (e.g. `fork_storm`,
   `nftables_churn`).
5. Per-op shm stats bumped via `__atomic_add_fetch`/`__atomic_store_n`
   (RELAXED) directly inside the childop — no separate stats-registration
   step.
6. Latching: ops that hit a kernel-support gap (`EOPNOTSUPP`, `EAFNOSUPPORT`,
   userns `-EPERM`) write one of `CHILDOP_LATCH_UNSUPPORTED` /
   `CHILDOP_LATCH_NS_UNSUPPORTED` / `CHILDOP_LATCH_INIT_FAILED` /
   `CHILDOP_LATCH_RESOURCE_EXHAUSTED` (include/child.h) into
   `shm->stats.childop_latch_reason[op]` and stop retrying permanently,
   vs. a transient `-EAGAIN`-class failure which just skips the iteration.

### Naming families (by filename, not by enum)

- `*-churn.c` (largest cluster, 41 files: `net/netfilter/nftables/churn.c`,
  `net/bridge-vlan-churn.c`, `net/tc/qdisc-churn.c`,
  `net/xfrm/xfrm-churn.c`, `fs/mount-churn.c`, `misc/cgroup-churn.c`, …)
  — repeated create/modify/destroy
  cycles against a kernel object family, racing teardown against live
  traffic/lookups. Several have split-out builder/internal companions
  (`net/tc/qdisc-churn-builders.c` + `-internal.h`,
  `net/xfrm/xfrm-churn-{builders,traffic,pfkey,sk-policy,ah-esn,compat-sweep}.c`
  + `-internal.h`,
  `net/netfilter/nftables/{builders,compat,dormant,fwd,l4frag,reject,xt}.c`,
  `net/netfilter/nftables/exprs-{conn,data,hash,nat,set,stateful}.c` +
  the `nftables/internal*.h` set)
  — these are non-dispatched
  helper units compiled into the same op, not separate childops.
- `*-race.c` (21 files: `net/af-unix-peek-race.c`,
  `fs/blkdev-lifecycle-race.c`, `misc/close-racer.c`, `fs/umount-race.c`,
  `mm/vdso-mremap-race.c`) — two threads/
  processes/timings pitted against each other around a narrow kernel
  window (usually construction vs. teardown, or two ioctls/syscalls raced
  via fork+barrier or SCM timing).
- `*-probe.c` (`net/af-alg-template-probe.c`,
  `net/af-alg-weak-cipher-probe.c`, `net/iscsi-target-probe.c`,
  `net/pkt-builder-probe.c`, `misc/netns-mountns-setup-probe.c`) —
  one-shot, read-only capability enumeration:
  try each variant, record accept/reject into shm stats, no destructive
  follow-up. Front-loaded EAFNOSUPPORT/EOPNOTSUPP short-circuit.
- `*-storm.c` / `*-thrash.c` / `*-flood.c` / `*-stress.c`
  (`misc/{fork-storm,futex-storm,signal-storm,pidfd-storm,fd-stress,
  pipe-thrash,slab-cache-thrash}.c`, `mm/{vma-split-storm,map-shared-stress}.c`,
  `fs/{xattr-thrash,flock-thrash}.c`, `io_uring/flood.c`) — bounded
  high-rate repetition
  of one cheap operation to pressure an allocator/hot path rather than
  race a specific window.
- `io_uring/recipes*.c` / `recipe/*.c` — a "recipe" sub-framework
  (see below) for multi-syscall object-lifecycle DAGs; several files
  per dispatched op.
- Everything else is one dispatched op per protocol/feature
  (`net/wireguard-decrypt-flood.c`, `fs/ublk-lifecycle.c`,
  `net/tls-rotate.c`, `net/psp-key-rotate.c`, `net/qrtr-bind-race.c`,
  etc.) named directly after the
  kernel subsystem it targets.

### Sub-framework: recipe/ and io_uring/

`recipe/runner.c` (216 lines) is the thin dispatched `CHILD_OP_RECIPE_RUNNER`
entry point; `recipe/internal.h` (98) defines the recipe DAG structures
shared by the catalogue — `recipe/simple.c` (185) plus its per-domain
companions `simple-mm.c` (401), `simple-fs.c` (277), `simple-timers.c`
(228), `simple-notify.c` (203) and `simple-sysv.c` (183) — together with
`recipe/net.c` (803), `recipe/close-race.c` (657),
`recipe/deadline-race.c` (841), and `recipe/supervisor.c` (1018,
forks/monitors/reaps the actual
recipe-executing children). A "recipe" is a small DAG: one syscall produces
a resource (fd/key/timer id), later steps consume it, one teardown step
frees it, and every path (success/partial-fail/structural-fail) converges
on a single `goto cleanup`. Recipe arg construction is deliberately
hand-picked (not random_syscall-driven) — the point is exercising the
*sequence*, not fuzzing individual args.

`io_uring/recipes.c` (725) is the dispatched `CHILD_OP_IOURING_RECIPES`
entry; `io_uring/recipes-{fs,net,poll-timeout,register}.c` and
`io_uring/recipes-internal.h`/`recipes.h` hold the per-domain recipe bodies
and shared ring-submission helpers. `io_uring/ring.c`/`ring.h` provide raw
io_uring SQ/CQ ring mapping independent of the recipes layer (also used
by `io_uring/flood.c`, `io_uring/cmd-passthrough.c`,
`io_uring/net-multishot.c`, `io_uring/send-zc-churn.c`).

### Largest/most complex individual files

| File | Lines | Role |
|---|---|---|
| `fs/tracefs-fuzzer.c` | 1755 | Exercise the tracefs/ftrace string-parsing interfaces (kprobe/uprobe event creation, `set_ftrace_filter`) |
| `net/igmp-mld-source-churn.c` | 1734 | IGMPv3 / MLDv2 source-filter mutation churn vs. live multicast traffic |
| `net/bridge-conntrack-churn.c` | 1673 | Race `IPCTNL_MSG_CT_FLUSH` against ingress traffic on an `NFPROTO_BRIDGE` conntrack chain |
| `mm/uffd-fault-move.c` | 1669 | Stateful UFFD fault + `UFFDIO_MOVE`/swap-cache race |
| `net/packet-qdisc-bypass-unanchored-l2.c` | 1640 | Probe `PACKET_QDISC_BYPASS` and AF_XDP copy-mode transmit with an unset skb MAC header on a macsec device |
| `net/tcp-ao-rotate.c` | 1577 | TCP-AO key add / rotate / delete race over a live loopback connection |
| `net/tc/qdisc-churn.c` | 1549 | Traffic-control qdisc/class/filter churn (the config plane) |
| `net/netfilter/nftables/internal-compat.h` | 1429 | UAPI fallback macros for nf_tables/netfilter/xfrm plus the xt/compat sweep and latch declarations |
| `net/af-unix-scm-rights-gc.c` | 1346 | Build a closed cycle in the AF_UNIX SCM_RIGHTS reference graph, then race `unix_gc` against concurrent `recvmsg()` draining |
| `io_uring/recipes-fs.c` | 1248 | Filesystem / openat / xattr / splice / tee / pipe / memfd recipe family |
| `net/netfilter/ipset-churn.c` | 1216 | ipset set/member lifecycle churn |
| `net/tc/live-traffic.c` | 1201 | Drive real packets through programmable tc filters while the filter chain is being replaced |
| `net/fnhe-pmtu-mtu-race.c` | 1190 | Race IPv4 PMTU exception table updates against concurrent nexthop MTU synchronisation |
| `net/vxlan-encap.c` | 1163 | VXLAN / GRE / GENEVE encap setup + packet inject, targeting teardown-vs-in-flight-tx on overlay tunnels |
| `misc/bpf-lifecycle.c` | 1035 | End-to-end BPF program lifecycle with map mutation |
| `recipe/supervisor.c` | 1018 | Forks/monitors/reaps the recipe-executing children |

## Key design decisions

1. **Enum + dense dispatch table, not per-file registration.** Every
   dispatched childop has a slot in `enum child_op_type` (`include/child.h`)
   and a matching entry in the `op_dispatch[NR_CHILD_OP_TYPES]` function
   pointer array in `child-altop-table.c`
   (`bool (*const op_dispatch[])(struct childdata *)`). `CHILD_OP_SYSCALL`
   maps to `NULL` — that case is the default random_syscall path and never
   reaches this table. A `_Static_assert` pins the table size to the enum
   count. Files are wired into the build by one `$(wildcard)` glob per
   childops subdirectory in `Makefile` — no separate manifest to edit for
   a new `.c` file in an existing subdirectory, but a *new subdirectory*
   needs its own glob line, and a new *dispatched op* still requires
   manually adding a
   row to `include/childop.def` (which expands into the enum, name switch,
   and `op_dispatch[]` slot) and picker coverage in `child-altop-pick.c`.
2. **File count > enum count.** 237 `.c` files but 168 dispatched ops
   (169 `childop.def` rows, of which `CHILD_OP_SYSCALL` is a sentinel
   expanding to a `NULL` dispatch slot):
   several ops are split across multiple files for size/cohesion
   (`net/netfilter/nftables/{builders,compat,dormant,fwd,l4frag,reject,xt}.c`,
   `net/netfilter/nftables/exprs-*.c`, `net/tc/qdisc-churn-builders.c`,
   `net/xfrm/xfrm-churn-*.c`, `io_uring/recipes-*.c`,
   `recipe/*.c`), sharing state through a private internal header.
   Only one file per group exports the dispatched entry point.
3. **Bounded-everything discipline.** Every storm/churn op caps rounds and
   per-round work with small compile-time constants, and long-running ops
   check wall-clock budgets via `budget_elapsed_ns()`
   (`include/childops-util.h`) rather than looping unconditionally. This
   exists because `child.c` arms `alarm(1)` around the whole childop call —
   a childop that runs long or hangs trips the SIGALRM stall detector, so
   ops self-limit to stay well under it rather than relying on the alarm as
   the only backstop.
4. **Namespace isolation for anything destructive/network-facing.**
   `userns_run_in_ns(CLONE_NEWNET, fn, arg)` (`include/userns-bootstrap.h`,
   implemented outside childops/) forks a grandchild into an owned user +
   net namespace; the childop's real work runs inside that grandchild so
   its `_exit()` tears down every socket/interface/table it created. A
   helper `-EPERM` (hardened userns policy) latches the whole op off
   permanently; `-EAGAIN` just skips one iteration.
5. **One-shot vs. permanent latching via `CHILDOP_LATCH_*`.** Kernel
   feature absence (`CHILDOP_LATCH_UNSUPPORTED`/`_NS_UNSUPPORTED`) and
   persistent init/resource failures latch the op off for the rest of the
   run via `shm->stats.childop_latch_reason[op]`; this is the standard way
   childops avoid burning cycles retrying a syscall path a given kernel
   build will never support.
6. **Netlink/genl/nfnl helper layering.** Protocol-churn childops don't
   hand-roll `sendmsg`/`recvmsg`: `include/childops-netlink.h` (raw
   `NETLINK_ROUTE`-style), `childops-genl.h` (generic netlink family
   resolution + messaging), and `childops-nfnl.h` (netfilter netlink,
   including batched transactions) provide open/close/send-recv/dump
   primitives with consistent `nl_ctx`/`genl_ctx`/`nfnl_ctx` handle types
   and `nla_put_*`/nest helpers for attribute construction, used across
   the bridge/nftables/xfrm/tc/rtnl-family files.
7. **Recipe DAGs deliberately bypass arg fuzzing.** `recipe-runner*.c` and
   `iouring-recipes*.c` construct syscall args inline with fixed/sane
   values rather than routing through trinity's normal sanitise/
   random_syscall arg generation — the goal is exercising a specific
   multi-syscall object-lifecycle sequence, and mixing in arg fuzz would
   make failures ambiguous (structural precondition miss vs. bad arg).
8. **KCOV_CMP harvest opt-in via a wrapper, not automatic.** `trinity_cmp_syscall()`
   (`include/childop-cmp.h`) is a drop-in replacement for the raw syscall
   wrapper at select childop callsites; it resets/collects KCOV CMP trace
   records into a quarantined `childop_recent_pools[nr]` lane (separate
   from the main cmp_hints pools) only when `--childop-cmp-harvest=on`,
   the calling op is inside an open `kcov_cmp_bracket`
   (`op_uses_outer_bracket()` gate in child.c), and the child is in
   CMP-collection mode. Elsewhere it degrades to a plain raw syscall.
9. **`struct childop_outcome` is telemetry-only.** `childop_outcome_snapshot()`
   (`include/child.h`) aggregates each op's edges/wall-time/wedges/crashes/
   timeouts from scattered `shm->stats.childop_*[op]` arrays into one
   record for dumps (`childop_outcome_window_dump()`,
   `childop_score_dump()` in `stats/`) — no scheduler, canary picker, or
   promotion/demotion logic reads it back.

## Integration points

- `child-altop-table.c` — the dispatch table (`op_dispatch[]`), the
  `enum child_op_type` → name switch, and `alt_op_lookup_by_name()`/
  `alt_op_name()` for CLI `--childop=<name>` selection.
- `child.c` — the per-iteration loop: calls `pick_op_type()`, bounds-checks
  the op, indexes `op_dispatch[op]` under `alarm(1)`, and gates
  bracket-owning ops via `op_uses_outer_bracket()`.
- `include/child.h` — `enum child_op_type`, `NR_CHILD_OP_TYPES`,
  `struct childop_outcome`, `CHILDOP_LATCH_*`, dormant-op accessors
  (`dormant_op_set`/`dormant_op_is_active`/`dormant_op_slot_for`).
- `include/childops-util.h`, `childops-netlink.h`, `childops-genl.h`,
  `childops-nfnl.h`, `childops-iouring.h`, `childop-cmp.h`,
  `userns-bootstrap.h` — the shared helper API surface every childop
  builds on (modprobe helper, budget timer, netlink/genl/nfnl transports,
  io_uring ring primitives, CMP-harvest wrapper, netns bootstrap).
- `include/stats.h`, `stats/stats.c`, `stats/dump.c` — per-childop counter
  arrays (`childop_edges_clean`, `childop_wall_ns`, `childop_wedge_count`,
  `childop_latch_reason`, `childop_data_path`, …) that childops write
  directly and stats/ renders back out.
- `cmp_hints/collect.c` — consumes the `childop_recent_pools[]` lane fed by
  `trinity_cmp_syscall()` calls inside childops.
- `main/params/options.c`, `main/params/coverage.c` — `--childop=`,
  `--no-childop=`, `--childop-cmp-harvest`
  CLI wiring that maps names to `enum child_op_type` via `child-altop-table.c`.
- `Makefile` — one `$(wildcard childops/<subdir>/*.c)` line per
  subdirectory builds every `.c` file
  unconditionally; no per-file enable/disable at build time.

## Areas of attention

1. **The `child-altop-*.c` cluster is a hidden fourth registration
   point.** Adding a new dispatched childop requires a coordinated set of
   edits across `include/childop.def` (the authoritative registry that
   feeds the enum, name switch, and `op_dispatch[]` slot in
   `child-altop-table.c`) and picker coverage plus any dormant-op /
   outer-bracket entries in `child-altop-pick.c`. Nothing in childops/
   itself enforces this; a `.c` file with no matching def-registry entry
   silently compiles but is never dispatched. The
   `check-alt-op-rotation` static check catches picker/registry
   mismatches.
2. **The `net/netfilter/nftables/` cluster** forms the single largest logical unit
   in the directory (~8550 LOC across the dispatched orchestrator, core
   builders, sub-mode files, six `exprs-*.c` companions, and five internal
   headers for one dispatched op).
   The internal header was itself split: `internal.h` (22) is now an
   umbrella over `internal-compat.h` (1429), `internal-state.h` (129),
   `internal-exprs.h` (62), `internal-builders.h` (47) and
   `internal-stats.h` (17).
   Understanding any one piece requires those shared
   struct/state declarations.
3. **Latching correctness is per-file, unenforced by any shared state
   machine.** Each childop hand-writes its own `CHILDOP_LATCH_*` decision
   tree from raw errno values (see the `net/netfilter/nftables/` cluster's distinct
   `ns_unsupported_*` latches); there's no shared errno-classification
   table specific to childops (though `errno-classify.h` exists generically),
   so latch logic correctness/completeness varies file to file.
4. **Namespace-escape blast radius.** Ops using `userns_run_in_ns()` run
   real destructive network/mount/device operations; correctness depends
   entirely on the grandchild's `_exit()` actually tearing down the netns
   — a childop that leaks a reference before exiting (e.g. a socket handed
   to another process, or an object registered outside the netns) would
   leave state on the host rather than in the disposable namespace.

## Summary

childops/ implements Trinity's scripted-sequence fuzzing tier: 168
dispatched multi-syscall workloads (storms, churns, races, probes, and a
recipe-DAG sub-framework) selected instead of a random syscall per child
iteration, each self-documenting its target kernel code path/CVE class in
a header comment, self-bounding via round/budget caps under child.c's
`alarm(1)`, self-isolating destructive work into throwaway user+net
namespaces, and self-latching off permanently when the running kernel
lacks the targeted feature. Wiring a childop into the fuzzer is manual and
centralized in `include/childop.def`'s registry (expanded into the enum,
name switch, and `op_dispatch[]` slot in `child-altop-table.c`), not
automatic from the file's presence in the directory.
