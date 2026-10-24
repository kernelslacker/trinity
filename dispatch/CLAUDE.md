# dispatch/ — Syscall Dispatch & Results

Issues the picked syscall, records its outcome, and tracks pid liveness — the tail of one fuzz iteration: `child/` picks (via `random_syscall/` + the `syscalls/` descriptor), this layer makes the call and books the result.

## Files

| File | Role |
|---|---|
| pids.c | Pid cache + liveness/kill/validity primitives (per-child cache set in `init_child()`). |

## Key invariants
- **syscallrecord bracket** — `rec->nr` / `a1..a6` / retval are published inside the srec bracket so an outside reader (watchdog, pre-crash decode) never sees a torn (nr, args) pair.
- **RET_* classification** — the raw return is mapped to success/failure and fed to results/kcov before the next iteration.
- **pid validity before kill** — `pids.c` re-checks a cached pid is still the process it recorded before signalling it, to avoid PID-recycling races.
- **EXTRA_FORK outcome** — the grandchild reports through the shared record: it publishes AFTER and the return value. A dispatch that never gets there (a failed `fork()`, `do_extrafork()` compiled out under ASAN, a grandchild killed or crashed) is counted `attempted` only, so `attempted - successes - failures` is its tally. A fork that fails with ENOMEM is reported to `pidns_note_fork_enomem()` (`child/child-pidns-init.c`), which recycles the child if a fuzzed syscall moved its forks into a pid namespace with no init. `--dry-run` never forks, having no call to contain; its synthesized outcome is recorded in the child. A live ASAN run does not draw these entries at all: `tables/` deactivates them at startup, and `--dry-run` keeps them so their sanitisers still run.
- **No kill after ECHILD** — `extrafork_reap()` signals its grandchild only when the poll budget runs out. ECHILD means the kernel already reaped it (SIGCHLD ignored or `SA_NOCLDWAIT`), so its pid may be someone else's.

## Areas of attention
- Arch-specific syscall numbers (biarch 32-on-64) resolve through `tables/`.
- EINTR / retry policy on the raw syscall.
- PID recycling — always re-validate a cached pid before acting on it.
