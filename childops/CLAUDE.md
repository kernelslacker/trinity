# childops/ — Scripted/stateful per-child fuzz workloads for Trinity

Trinity's default fuzzing loop (`random_syscall/`) picks one syscall in
isolation per iteration. Many kernel bug classes (UAF/refcount races,
teardown-vs-lookup races, multi-step object lifecycles) only surface when a
specific *sequence* of syscalls runs with real state threaded through it.
childops/ is where those scripted sequences live: each file implements one
"childop" — a self-contained C function, dispatched instead of a random
syscall for the current fork'd child, that drives a fixed or semi-fixed
sequence against one kernel subsystem/feature/race window.

138 `.c` files + 7 internal `.h` files, ~81,300 LOC total.

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
   `enum child_op_type` case in `child-altop.c` (e.g. `fork_storm`,
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

- `*-churn.c` (largest cluster, ~35 files: `nftables-churn.c`,
  `bridge-vlan-churn.c`, `tc-qdisc-churn.c`, `xfrm-churn.c`,
  `mount-churn.c`, `cgroup-churn.c`, …) — repeated create/modify/destroy
  cycles against a kernel object family, racing teardown against live
  traffic/lookups. Several have split-out `-builders`/`-internal.h`
  companions (`tc-qdisc-churn-builders.c` + `-internal.h`,
  `xfrm-churn-builders.c` + `-internal.h`, `nftables-churn-exprs-{conn,
  data,hash,nat,set,stateful}.c` + `-internal.h`) — these are non-dispatched
  helper units compiled into the same op, not separate childops.
- `*-race.c` (~20 files: `af-unix-peek-race.c`, `blkdev-lifecycle-race.c`,
  `close-racer.c`, `umount-race.c`, `vdso-mremap-race.c`) — two threads/
  processes/timings pitted against each other around a narrow kernel
  window (usually construction vs. teardown, or two ioctls/syscalls raced
  via fork+barrier or SCM timing).
- `*-probe.c` (`af-alg-template-probe.c`, `af-alg-weak-cipher-probe.c`,
  `iscsi-target-probe.c`) — one-shot, read-only capability enumeration:
  try each variant, record accept/reject into shm stats, no destructive
  follow-up. Front-loaded EAFNOSUPPORT/EOPNOTSUPP short-circuit.
- `*-storm.c` / `*-thrash.c` / `*-flood.c` (`fork-storm.c`,
  `futex-storm.c`, `signal-storm.c`, `fd-stress.c`, `xattr-thrash.c`,
  `slab-cache-thrash.c`, `iouring-flood.c`) — bounded high-rate repetition
  of one cheap operation to pressure an allocator/hot path rather than
  race a specific window.
- `iouring-recipes*.c` / `recipe-runner*.c` — a "recipe" sub-framework
  (see below) for multi-syscall object-lifecycle DAGs; several files
  per dispatched op.
- Everything else is one dispatched op per protocol/feature
  (`wireguard-decrypt-flood.c`, `ublk-lifecycle.c`, `tls-rotate.c`,
  `psp-key-rotate.c`, `qrtr-bind-race.c`, etc.) named directly after the
  kernel subsystem it targets.

### Sub-framework: recipe-runner / iouring-recipes

`recipe-runner.c` (191 lines) is the thin dispatched entry point;
`recipe-runner-internal.h` defines the recipe DAG structures shared by
`recipe-runner-simple.c` (1023), `recipe-runner-net.c` (725),
`recipe-runner-close-race.c` (629), `recipe-runner-deadline-race.c` (734),
and `recipe-runner-supervisor.c` (1048, forks/monitors/reaps the actual
recipe-executing children). A "recipe" is a small DAG: one syscall produces
a resource (fd/key/timer id), later steps consume it, one teardown step
frees it, and every path (success/partial-fail/structural-fail) converges
on a single `goto cleanup`. Recipe arg construction is deliberately
hand-picked (not random_syscall-driven) — the point is exercising the
*sequence*, not fuzzing individual args.

`iouring-recipes.c` (649) is the dispatched `CHILD_OP_IOURING_RECIPES`
entry; `iouring-recipes-{fs,net,poll-timeout,register}.c` and
`iouring-recipes-internal.h`/`.h` hold the per-domain recipe bodies and
shared ring-submission helpers. `iouring-ring.c`/`.h` provide raw
io_uring SQ/CQ ring mapping independent of the recipes layer (also used
by `iouring-flood.c`, `iouring-cmd-passthrough.c`,
`iouring-net-multishot.c`, `iouring-send-zc-churn.c`).

### Largest/most complex individual files

| File | Lines | Role |
|---|---|---|
| `nftables-churn.c` | 2498 | Full table/chain/set/rule lifecycle churn in a private netns, racing live loopback traffic through the commit path (targets CVE-2024-1086, CVE-2023-32233, CVE-2024-26642/26581, CVE-2023-3390 lineage) |
| `nftables-churn-internal.h` | 1541 | Shared nftables-churn message-builder declarations/state used by the `-exprs-*.c` split files |
| `nl80211-churn.c` | 1378 | cfg80211/nl80211 interface + BSS churn |
| `xfrm-churn.c` | 1298 | IPsec policy/state (XFRM) churn |
| `psp-key-rotate.c` | 1229 | PSP (TLS offload) key rotation races |
| `nat-t-churn.c` | 1217 | NAT-T/ESP encapsulation churn |
| `afxdp-churn.c` | 1202 | AF_XDP ring/umem lifecycle churn |
| `bridge-fdb-stp.c` | 1122 | Bridge FDB entry churn interleaved with STP state transitions |
| `recipe-runner-supervisor.c` | 1048 | Forks/deadlines/reaps the recipe-executing grandchildren for the recipe-runner sub-framework |
| `tc-qdisc-churn.c` | 1031 | Traffic-control qdisc/class/filter churn |
| `af-unix-scm-rights-gc.c` | 1024 | AF_UNIX SCM_RIGHTS garbage-collection race (in-flight fd refcounting) |
| `recipe-runner-simple.c` | 1023 | Straight-line (non-racing) recipe DAGs |

## Key design decisions

1. **Enum + dense dispatch table, not per-file registration.** Every
   dispatched childop has a slot in `enum child_op_type` (`include/child.h`)
   and a matching entry in the `op_dispatch[NR_CHILD_OP_TYPES]` function
   pointer array in `child-altop.c`
   (`bool (*const op_dispatch[])(struct childdata *)`). `CHILD_OP_SYSCALL`
   maps to `NULL` — that case is the default random_syscall path and never
   reaches this table. A `_Static_assert` pins the table size to the enum
   count. Files are wired into the build by `Makefile`'s
   `$(wildcard childops/*.c)` glob — no separate manifest to edit for a new
   `.c` file, but a new *dispatched op* still requires manually adding the
   enum value, the `case … return "name"` in the name-lookup switch, and the
   `op_dispatch[]` slot, all in `child-altop.c`.
2. **File count > enum count.** 138 `.c` files but ~118 dispatch slots:
   several ops are split across multiple files for size/cohesion
   (`nftables-churn-exprs-*.c`, `tc-qdisc-churn-builders.c`,
   `xfrm-churn-builders.c`, `iouring-recipes-*.c`,
   `recipe-runner-*.c`), sharing state through a private `*-internal.h`.
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

- `child-altop.c` — the dispatch table (`op_dispatch[]`), the
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
- `params.c` — `--childop=`, `--no-childop=`, `--childop-cmp-harvest`
  CLI wiring that maps names to `enum child_op_type` via `child-altop.c`.
- `Makefile` — `$(wildcard childops/*.c)` builds every `.c` file
  unconditionally; no per-file enable/disable at build time.

## Areas of attention

1. **`child-altop.c` is a hidden fourth registration point.** Adding a new
   dispatched childop requires four synchronized edits spread across one
   1400+-line file (enum value, name-switch case, `op_dispatch[]` slot,
   plus often a `dormant_op`/outer-bracket table entry) — nothing in
   childops/ itself enforces this; a `.c` file with no matching enum/table
   entry silently compiles but is never dispatched.
2. **`nftables-churn.c` (2498 lines) plus its 1541-line internal header
   and six `-exprs-*.c` companions** form the single largest logical unit
   in the directory (~5000+ LOC across ~8 files for one dispatched op).
   Understanding any one piece requires the internal header's shared
   struct/state declarations.
3. **Latching correctness is per-file, unenforced by any shared state
   machine.** Each childop hand-writes its own `CHILDOP_LATCH_*` decision
   tree from raw errno values (see `nftables-churn.c`'s dozen distinct
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

childops/ implements Trinity's scripted-sequence fuzzing tier: ~118
dispatched multi-syscall workloads (storms, churns, races, probes, and a
recipe-DAG sub-framework) selected instead of a random syscall per child
iteration, each self-documenting its target kernel code path/CVE class in
a header comment, self-bounding via round/budget caps under child.c's
`alarm(1)`, self-isolating destructive work into throwaway user+net
namespaces, and self-latching off permanently when the running kernel
lacks the targeted feature. Wiring a childop into the fuzzer is manual and
centralized in `child-altop.c`'s enum + dispatch table, not automatic from
the file's presence in the directory.
