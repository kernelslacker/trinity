# child/ — Child Runtime Loop

Each forked child's per-iteration lifecycle: bring-up + sandbox, then the loop that runs one workload per iteration — either a random syscall (`random_syscall/`) or a scripted childop (`childops/`) via the alt-op picker — under an `alarm()` backstop and a set of self-integrity oracles. Distinct from `childops/`: those are the scripted *workloads*; this is the runtime *infrastructure* that drives them.

## Files (19 files, ~6,400 LOC)

| File | Role |
|---|---|
| child.c | The per-child loop: init → iterate (alt-op vs random syscall → dispatch → record) → reap. The heart of a child's life. |
| child-init-core.c | `init_child()` coordinator: the readable phase map that sequences the sibling child-init-* phase files. |
| child-init-clean.c | Coredump toggles, fault-injection fd setup (make-it-fail, fail-nth), tainted-mask fd, FPU dirtier, per-slot occupant reset (`clean_childdata`). |
| child-init-isolate.c | Stdio + controlling-terminal isolation: fd 0/1/2 → `/dev/null`, parent-fd drops (`--stats-log-file`, self-cgroup, `/proc/<pid>/stat`), `setsid()`. |
| child-init-freeze.c | Initial sibling-childdata + shared-region `mprotect(PROT_READ)` sweeps, parent rendezvous, per-child object-pool bring-up, optional CPU pin. |
| child-init-sandbox.c | `shm->ready` barrier, fault-injector arm, per-child unshare()s, root-only `drop_privs`, `capset()`-to-empty + oracle anchor capture, rlimit / cgroup / umask sweep. |
| child-init-runtime.c | kcov bring-up, uniarch active-syscalls pin, explorer-pool slot flag, A/B-comparison cohort stamps, heap-bounds re-snapshot, `RLIMIT_AS` pin, one-shot `disable_coredumps`. |
| child-altop-pick.c | Alt-op picker + dedicated-child rotation + dormant-op gate: `pick_op_type()` / `pick_op_type_table[]` / `alt_op_rotation[]` / `assign_dedicated_alt_op()` / `init_altop_dispatch()` (gated by `scripts/check-static/check-alt-op-rotation.sh`). |
| child-altop-table.c | Alt-op string names + indirect-call dispatch: `op_dispatch[]` / `alt_op_name()` / `alt_op_lookup_by_name()` / `op_uses_outer_bracket()` (gated by `scripts/check-static/childop-arrays.sh`). |
| child-altop-budget.c | Adaptive per-op budget multiplier + decaying-recency edge/wall ring: `adapt_budget()` / `childop_decay_record_*()` / `childop_window_advance()`. |
| child-altop-score.c | Per-op outcome snapshot + ranked score-dump tables emitted at shutdown: `childop_outcome_snapshot()` / `childop_outcome_window_dump()` / `childop_score_dump()`. Telemetry-only. |
| child-canary-state.c | Dormant-childop canary promotion queue: state transitions (`enter_canarying` / `leave_canarying_*` / `close_window_and_decide`) + `canary_queue_init` + the two-stage commit-on-respawn hook. |
| child-canary-picker.c | Canary picker (`pick_next_canary`) + `~1-s` tick loop (`canary_queue_tick`), including early-bail SETUP_BROKEN and wedge-stall demotes and the plateau-edge log. |
| child-canary-policy.c | Canary static policy tables: priority seeds, config-blocked terminals, risky-defer skip set, pid-heavy drain set, and the op → setup-failure reason hint table. |
| child-canary-report.c | Canary summary/log emitters (`canary_queue_summary`, `canary_queue_on_crash`) + the read-only public queries (`canary_slot_active`, `canary_active_op`, `canary_op_is_promoted`) called on every fork. |
| child-sentinel.c | Deterministic-divergence sentinel: flags when a child's execution diverges from the expected deterministic path (a state-corruption tell). |
| child-capdrop-oracle.c | Post-capdrop assertion: verifies the child actually dropped to an empty capability set (fuzzing must never run privileged). |
| cred_throttle.c | Credential-change oracle / throttle: gates how often a child mutates its own creds and checks the outcome. |

## Key invariants
- **`alarm()` backstop** — every child arms an alarm so an indefinite-blocking syscall can't wedge it (paired with the per-syscall `NEED_ALARM` flag).
- **PDEATHSIG + getppid recheck** — arm `PR_SET_PDEATHSIG`, then re-check `getppid()` to close the parent-died-before-prctl race (gated by `pdeathsig-getppid-recheck.sh`).
- **Cap-drop verified, not assumed** — `child-capdrop-oracle.c` asserts the empty cap set; a child that failed to drop is a bug, not a fuzz finding.
- **child-context-output** — child-side `output()`/`outputerr()` writes are `/dev/null`-redirected and baselined (`child-context-output.baseline`); new child-side output callsites shift that baseline.

## Interactions
- **`random_syscall/`** — the fresh/biased/replay pick for a non-alt-op iteration.
- **`childops/`** — the scripted workloads the alt-op picker dispatches.
- **syscall dispatch + `results.c`** — issues the syscall and records the outcome (`dispatch/`).
- **`objects/`** — the per-child object pool feeding fd/id/handle args.

## Areas of attention
- Alt-op scoring / canary-promotion cadence live here; the *workloads* live in `childops/`.
- Signal-mask policy is in `health/signals.c`, NOT here.
- child-context-output baseline is line-sensitive — a pure code-motion move preserves line numbers, but new output callsites shift it.
