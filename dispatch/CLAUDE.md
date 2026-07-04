# dispatch/ — Syscall Dispatch & Results

Issues the picked syscall, records its outcome, and tracks pid liveness — the tail of one fuzz iteration: `child/` picks (via `random_syscall/` + the `syscalls/` descriptor), this layer makes the call and books the result.

## Files (3 files, ~2,400 LOC)

| File | Role |
|---|---|
| syscall.c | The `do_syscall()` machinery: entry/exit wrappers, the actual syscall invocation, and post-call bookkeeping (kcov/cmp collection, result classification, post_state/oracle handling). |
| results.c | Per-syscall result counters / scoreboards — the success/failure/errno tallies the picker and stats read. |
| pids.c | Pid cache + liveness/kill/validity primitives (per-child cache set in `init_child()`). |

## Key invariants
- **syscallrecord bracket** — `rec->nr` / `a1..a6` / retval are published inside the srec bracket so an outside reader (watchdog, pre-crash decode) never sees a torn (nr, args) pair.
- **RET_* classification** — the raw return is mapped to success/failure and fed to results/kcov before the next iteration.
- **pid validity before kill** — `pids.c` re-checks a cached pid is still the process it recorded before signalling it, to avoid PID-recycling races.

## Interactions
- Called from **`child/`** (the dispatch step of the child loop).
- Syscall number → descriptor via **`tables/`**; args from **`args/`** and the generators.
- Feeds outcomes to **`stats/`** and **`kcov/`** / **`cmp_hints/`**.

## Areas of attention
- Arch-specific syscall numbers (biarch 32-on-64) resolve through `tables/`.
- EINTR / retry policy on the raw syscall.
- PID recycling — always re-validate a cached pid before acting on it.
