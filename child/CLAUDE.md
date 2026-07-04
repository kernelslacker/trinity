# child/ — Child Runtime Loop

Each forked child's per-iteration lifecycle: bring-up + sandbox, then the loop that runs one workload per iteration — either a random syscall (`random_syscall/`) or a scripted childop (`childops/`) via the alt-op picker — under an `alarm()` backstop and a set of self-integrity oracles. Distinct from `childops/`: those are the scripted *workloads*; this is the runtime *infrastructure* that drives them.

## Files (7 files, ~6,400 LOC)

| File | Role |
|---|---|
| child.c | The per-child loop: init → iterate (alt-op vs random syscall → dispatch → record) → reap. The heart of a child's life. |
| child-init.c | Child bring-up: sandbox setup, fd/map/object pool init, cred/cap drop, per-child cache seeding, `/dev/null` output redirect. |
| child-altop.c | Alt-op picker: `op_dispatch[]` / `alt_op_name()` / `pick_op_type_table[]` / `alt_op_rotation[]` — the childop-vs-syscall selection tables (gated by `scripts/check-static/{childop-arrays,check-alt-op-rotation}.sh`). |
| child-canary.c | Dormant-childop canary promotion: periodically re-probes a cooled/dormant op to see if it's productive again. |
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
- **syscall dispatch + `results.c`** — issues the syscall and records the outcome (root today; `dispatch/` after the dispatch carve).
- **`objects/`** — the per-child object pool feeding fd/id/handle args.

## Areas of attention
- Alt-op scoring / canary-promotion cadence live here; the *workloads* live in `childops/`.
- Signal-mask policy is in `signals.c` (root today; `health/` later), NOT here.
- child-context-output baseline is line-sensitive — a pure code-motion move preserves line numbers, but new output callsites shift it.
