# dispatch/ — Syscall Dispatch & Results

Issues the picked syscall, records its outcome, and tracks pid liveness — the tail of one fuzz iteration: `child/` picks (via `random_syscall/` + the `syscalls/` descriptor), this layer makes the call and books the result.

## Files (9 files, ~2,670 LOC)

The `do_syscall()` machinery is split across `syscall*.c`: `syscall.c` keeps only
the entry point, with the execution path and the return-side phases in their own
translation units.

| File | Role |
|---|---|
| syscall.c | Top-level coordinator: the `do_syscall()` entry point, picking between the common in-child path and the EXTRA_FORK throwaway-grandchild wrapper (`--dry-run` always takes the in-child path). |
| syscall-exec.c | Raw execution path: biarch 32-on-64 dispatch, fail-nth fault injection, in-child watchdog fd eviction, the SHADOW noisy-sample bracket, the `__do_syscall` bracket, and `do_extrafork()`. |
| extrafork-reap.c | `extrafork_reap()`: the wait-then-kill that ends `do_extrafork()`'s throwaway grandchild. |
| syscall-return.c | `handle_syscall_ret()` coordinator and its three phase helpers, in the preserved order: validate → dispatch → post. |
| syscall-post.c | Generic close-fd hook, post-state / rettype bound validators, and ENOSYS deactivation. |
| syscall-retfd.c | fd return validation and registration. |
| syscall-arena.c | Arena stale/liveness probes. |
| results.c | Per-syscall result counters / scoreboards — the success/failure/errno tallies the picker and stats read. |
| pids.c | Pid cache + liveness/kill/validity primitives (per-child cache set in `init_child()`). |

## Key invariants
- **syscallrecord bracket** — `rec->nr` / `a1..a6` / retval are published inside the srec bracket so an outside reader (watchdog, pre-crash decode) never sees a torn (nr, args) pair.
- **RET_* classification** — the raw return is mapped to success/failure and fed to results/kcov before the next iteration.
- **pid validity before kill** — `pids.c` re-checks a cached pid is still the process it recorded before signalling it, to avoid PID-recycling races.
- **EXTRA_FORK outcome** — the grandchild reports through the shared record: it publishes AFTER and the return value. A dispatch that never gets there (a failed `fork()`, `do_extrafork()` compiled out under ASAN, a grandchild killed or crashed) is counted `attempted` only, so `attempted - successes - failures` is its tally. `--dry-run` never forks, having no call to contain; its synthesized outcome is recorded in the child. A live ASAN run does not draw these entries at all: `tables/` deactivates them at startup, and `--dry-run` keeps them so their sanitisers still run.
- **No kill after ECHILD** — `extrafork_reap()` signals its grandchild only when the poll budget runs out. ECHILD means the kernel already reaped it (SIGCHLD ignored or `SA_NOCLDWAIT`), so its pid may be someone else's.

## Interactions
- Called from **`child/`** (the dispatch step of the child loop).
- Syscall number → descriptor via **`tables/`**; args from **`args/`** and the generators.
- Feeds outcomes to **`stats/`** and **`kcov/`** / **`cmp_hints/`**.

## Areas of attention
- Arch-specific syscall numbers (biarch 32-on-64) resolve through `tables/`.
- EINTR / retry policy on the raw syscall.
- PID recycling — always re-validate a cached pid before acting on it.
