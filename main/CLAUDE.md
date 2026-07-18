# main/ — Parent Process Orchestration Layer

The Trinity parent process: the entry point (`trinity.c`) and CLI/tunable
parsing (`params/`), then the control plane that forks and tracks the fuzzer
child fleet, reaps exits, runs the D-state/stuck watchdog, and drives the
periodic stats/health dump. `trinity.c`'s `main()`/`epoch_loop()` sets up and
repeatedly calls `main_loop()`; none of this fuzzes anything itself.

## Files

| File | Role |
|---|---|
| trinity.c | Process entry: `main()`, option/table setup, `warm_start_all()`, and the epoch loop that repeatedly calls `main_loop()`. Does not fuzz. |
| params/ | CLI option parsing and the global tunables/flags the rest of the codebase reads (targeting, `--childop`, richness levers). Split by concern -- see the subdirectory breakdown below. |
| main/loop.c | `main_loop()` driver: per-tick phase sequencing (drain → stop-checks → periodic surfaces → fork-replace), epoch reset (`reset_epoch_state`), `panic()` |
| main/reap.c | Reap + watchdog: `waitpid(-1)` drain, zombie/D-state slot deferral, stuck-child SIGKILL escalation, fork-die-respawn loop detector, shm corruption sanity checks |
| main/spawn.c | `fork_children()`/`spawn_child()`: slot allocation, fork-failure backoff/bail, fork-pressure drain, forensic snapshots, final cross-run state save |
| main/stats.c | `print_stats()`: KCOV/CMP diagnostic lines, picker/plateau/pool-ratio dumps, per-op-count-delta throttling |

### `main/params/` subdirectory

CLI parsing was split out of the single `main/params.c` translation unit so
adding a knob only touches the file that owns that knob's concern.  All
externally-visible parser symbols still live in `include/params.h`; anything
inside `main/params/` is params-cluster private and declared in
`main/params/internal.h`.

| File | Role |
|---|---|
| `internal.h` | Params-private helper + option-family declarations shared across `main/params/*.c`. Not exported outside this cluster. |
| `state.c` | Definitions of the global tunable storage (booleans, strings, mode enums) the rest of the codebase reads. |
| `defaults.c` | `derive_max_children_cap()` + `clamp_default_*()` helpers `main()` calls after `parse_args()` finalises operator input. |
| `help.c` | `option_descs[]`, `shortonly_descs[]` and `usage()` -- the `--help` output. |
| `options.c` | `paramstr` and `longopts[]` -- the `getopt_long()` metadata. |
| `parse.c` | `parse_args()` orchestrator, `parse_duration()`/`parse_unsigned()` scalar helpers shared by every family. |
| `selection.c` | Arch/syscall/domain/group/-r/-N/-s/-V selection knobs plus the comma-list csv helper. |
| `runtime.c` | Epoch/max-runtime, stats, memory-cgroup, warm-start cache options. |
| `coverage.c` | KCOV/CMP/frontier/reach/blob/cmsg strategy knobs (also currently owns the canary + fork-pressure rows the phase-2 spec will move into `childop.c`). |
| `childop.c` | Child-slot sizing: `-C`, `--alt-op-children`, `--explorer-children`. |
| `debug.c` | writer-pin canary, `--guard-shared`, verbosity/diagnostics, `-h`/`-L`/`-I`/`-b` info commands, misc long-only flags. |
| `compat.c` | Backwards-compat parser helpers: `--redqueen-pending-pick` name/parser pair and the `enable_disable_fd_usage()` hook `usage()` calls. |

Roles match the guessed split exactly: main/loop.c is the loop, main/spawn.c
forks, main/reap.c reaps/watches, main/stats.c prints. All four share
parent-private state declared in `include/main-internal.h` (`pidstatfiles`,
`zombie_pids`, `zombie_since`, `spawn_times`, `hiscore`, `stall_count`) —
this header is the internal seam for the main/loop.c 4-way split, not a public
API surface.

## Process lifecycle

- **Slot model**: `max_children` fixed-size slots, indexed by `childno`,
  backed by `pids[]` in shm and `children[]` (childdata) also in shm.
  `spawn_child()` forks via `self_cgroup_fork_into_workload()`, writes
  `pids[childno]` last (release store) so the child spins in `init_child()`
  until its own pid is visible.
- **No SIGCHLD handler**: reaping is pure polling. `reap_dead_kids()` does
  `waitpid(-1, WNOHANG)` in a bounded loop (cap 64) each tick, because
  SIGCHLD is edge-triggered and a per-slot `waitpid()` walk can fall behind
  when multiple children die in one tick (observed: 22 stuck `<defunct>`
  under a crash storm). A second pass does `kill(pid, 0)`+ESRCH to catch
  slots the first pass's bookkeeping missed.
- **Two-tier dead-slot handling**: a normally-exiting/signaled child goes
  through `reap_child()` immediately (clears `pids[i]`, decrements
  `running_childs`, tears down pre-crash ring / bug-backtrace / fault
  beacon). A child stuck in kernel D-state cannot be reaped safely — its
  task struct can still write into childdata after the slot looks empty —
  so it's parked in `zombie_pids[]`/`zombie_since[]` via
  `register_zombie_slot()` and only handed back to `find_free_childno()`
  once a later `waitpid(WNOHANG)` in `process_zombie_pending()` confirms
  the kernel actually released it (or `ZOMBIE_REAP_TIMEOUT_SEC`=300s
  elapses and the slot is force-reused, logged loudly).
- **Stuck-child escalation**: `is_child_making_progress()` compares
  `child->tp` (last progress timestamp) each tick; at 30s idle it dumps a
  D-state diagnostic snapshot (wchan/stack/fdinfo, epoll/select fd
  topology) once and sends SIGKILL; if still alive at 40s it repeats
  SIGKILL every tick. `kill_count >= 10` routes the slot into
  zombie-pending regardless of D/S state, since SIGKILL cannot preempt
  D-state. If every running child is simultaneously stalled,
  `stall_genocide()` randomly SIGKILLs ~1/4 of the fleet to break a
  fleet-wide wedge.
- **Pacing**: no sleep-based pacing in the steady state — `handle_children()`
  only `usleep(25000)`s when a `waitpid` pass collects nothing. Fork storms
  self-throttle: `fork_throttle_us` (set from cgroup memory.high
  back-pressure) sleeps before each `spawn_child()` and yields back to
  `main_loop` after one spawn so reap/drain get a turn; `fork_pressure_drain`
  suppresses pid-heavy canary ops for 30s once 100 consecutive spawn
  failures accumulate.
- **Corruption/limit detection**: `shm_is_corrupt()` checks op-count
  monotonicity, the `shm_published` mirror page, and pid sanity every tick;
  `check_main_loop_stops()` also handles targeted-mode (`-c`/`-r`/`-g`)
  self-depletion, op-count/epoch-iteration/epoch-timeout limits (via
  `panic()`, which just stamps `shm->exit_reason` for the loop to notice
  next pass), and drains locks held by now-dead children.
- **Fast-die loop detector**: `record_reap()` keeps a 16-entry ring of
  recent reap outcomes; if all 16 are "died within 2s, non-zero exit"
  it declares a fork-die-respawn busy-loop (symptomatic of shm corruption
  making every fresh child immediately trip a startup check) and panics
  `EXIT_SHM_CORRUPTION`. Several `exit_reason` values (clean targeted-mode
  exits, SIGINT, epoch/count-reached) are explicitly excluded from
  counting as fast-die so legitimate rapid clean shutdowns don't
  false-positive this detector.

## Key design decisions

1. **Poll, don't trap** — SIGCHLD is never handled by a signal handler in
   the parent (grep confirms zero `signal(SIGCHLD, ...)` install sites
   outside children/childops); all reaping is `waitpid(WNOHANG)` polling
   from `main_loop`'s tick. This sidesteps async-signal-safety entirely for
   the reap path at the cost of edge-triggered-signal loss, which is why
   `reap_dead_kids()` drains via `waitpid(-1)` rather than one pid at a time.
2. **Slot reuse gated on kernel teardown, not just `pids[i]==EMPTY`** —
   `find_free_childno()` requires both `pids[i]` and `zombie_pids[i]`
   empty. This exists specifically to close a PID-reuse-adjacent hazard:
   a D-state predecessor task can still write into childdata (fd_event_ring,
   `tp`) after its slot looks free; handing the slot to a replacement child
   before the kernel confirms teardown corrupts the new child's state.
3. **In-process epoch loop** — `trinity.c`'s `epoch_loop()` calls
   `main_loop()` repeatedly in the same parent process (a past design ran
   each epoch as a forked child); `reset_epoch_state()` clears per-epoch
   counters while deliberately preserving coverage state (kcov bitmap,
   cmp_hints pool, minicorpus, bandit arm state) across epoch boundaries.
4. **`panic()` is a deferred, non-blocking stop signal** — it only stamps
   `shm->spawn_no_more`/`shm->exit_reason`; the actual unwind happens on
   the main_loop while-condition's next check, giving in-flight per-tick
   work (drain, watchdog kill) one more pass to run cleanly before the
   loop exits.
5. **Bounded backoff everywhere in the spawn path** — per-slot retry cap
   (10), outer consecutive-failure cap (1000, ~1 min of 10-100ms backoff),
   and a cumulative per-`fork_children()`-call backoff cap (2s) that yields
   back to `main_loop` mid-refill so reap/watchdog aren't starved during a
   sustained fork-pressure episode.
6. **One-shot forensic snapshots on the bail path** — fork-failure,
   fast-die-loop, and D-state-stuck all have latched (`static bool
   emitted`) one-time dumps (`/proc/self/status`, cgroup pids/memory.events,
   pid-state histogram, subworker fork-failure counters) so a wedged fleet
   produces one diagnostic block instead of flooding the log.
7. **Stats output is self-throttled and change-gated** — `print_stats()`
   only fires every 10,000 ops; several sub-lines (KCOV CMP/PC diag,
   PICKER, explorer/bandit ratio) additionally suppress repeats of an
   unchanged line and force a re-print only every 30 windows, keeping
   steady-state logs quiet without losing a periodic state anchor.

## Integration points

- `trinity.c` — top-level caller: `warm_start_all()` before entry,
  `epoch_loop()`/direct `main_loop()` call, `persist_state_on_clean_exit()`
  mirrors `final_state_save()`'s save set on the clean-exit path.
- `child.c` / `child-init.c` — `spawn_child()` forks into `child_process()`
  (child.c); child startup blocks in `init_child()` until the parent
  publishes `pids[childno]`.
- `shm.h` / shared childdata (`children[]`, `pids[]`) — the entire slot
  model; `shm->running_childs`, `shm->exit_reason`, `shm->spawn_no_more`,
  `shm->ready` are the cross-process coordination fields.
- `stats.c`, `stats_ring.c`, `stats/periodic.c`, `stats/runid.c` — per-tick
  ring drain (`stats_ring_drain_all`), periodic dump helpers called from
  `run_periodic_surfaces()`, run-identity snapshot at loop entry.
- `kcov.h`, `kcov/plateau.c`, `kcov/persist.c` — `kcov_plateau_check()`,
  `kcov_bitmap_maybe_snapshot()`/`kcov_bitmap_canary_check()`,
  KCOV CMP/PC diagnostic formatting consumed by main/stats.c.
- `cmp_hints.c`, `cmp_hints/persist.c` — `cmp_hints_maybe_snapshot()`
  each tick; `final_state_save()` calls `cmp_hints_save_file()` on the
  fork-failure bail path.
- `minicorpus.c` — `minicorpus_mut_attrib_canary_check()`,
  `minicorpus_save_file()` in `final_state_save()`, chain-corpus snapshot
  trigger (`chain_corpus_maybe_snapshot()`).
- `self_cgroup.c` — `self_cgroup_events_check()` per tick,
  `self_cgroup_fork_into_workload()` for the actual fork, memory.high
  back-pressure feeds `fork_throttle_us`.
- `child-canary.c` / canary queue — `canary_queue_init()`,
  `canary_queue_on_child_respawn()`, `canary_queue_on_crash()`,
  `canary_queue_tick()`, `fork_pressure_drain_active()` consumed by the
  canary picker to suppress pid-heavy ops during fork pressure.
- `child-altop.c` — `init_altop_dispatch()`/`assign_dedicated_alt_op()` for
  dedicated-alt-op child slots.
- `random.c` — `reseed()` on every replacement spawn and on epoch reset.
- `locks.c` — `check_all_locks()`/`force_bust_lock()` for lock recovery
  after a child dies holding the syscall dispatch lock.
- `pids.c` / `pid_is_valid`/`pid_alive`/`kill_pid` — pid-liveness and
  signal-delivery primitives used throughout reap/spawn.
- `kmsg-monitor.c` — `kmsg_monitor_note_reaped()` notified when
  `reap_dead_kids()` reaps an untracked pid, in case it was the kmsg
  helper process (which lives outside the fuzz-child `pids[]` machinery).

## Areas of attention

1. **main/reap.c size and responsibility span** (1,803 LOC) — covers shm
   corruption sanity, normal reap, zombie/D-state deferral, watchdog
   escalation, D-state forensic dumping (5 separate bounded `/proc` readers),
   fast-die-loop ring detection, and signal-status dispatch. A change to
   any one sub-concern (e.g. the D-state diagnostic format) risks
   collateral edits across an 1,800-line file with no sub-file boundary.
2. **Slot-reuse correctness is load-bearing and documented but easy to
   violate on a future edit** — `find_free_childno()`'s double-empty check
   (`pids[i]` AND `zombie_pids[i]`) is the sole guard against the
   documented D-state-write-after-reap corruption case; any new code path
   that reaps a slot without going through `reap_child()` +
   `register_zombie_slot()`'s logic would reopen that hole.
3. **`bail_fast_die_loop()`'s exclusion list is a maintenance trap** —
   `reap_entry_is_fast_die()` hardcodes five `exit_reason` values as
   "expected fast clean exit, don't count toward the corruption ring."
   Any future exit path that legitimately exits quickly and cleanly (new
   operator-driven shutdown reason, new targeted-mode depletion path) must
   remember to add itself here or risk a false-positive
   `EXIT_SHM_CORRUPTION` panic under adversarial timing.
4. **`panic()`'s deferred-effect design means every caller must reason
   about one extra tick of execution** — code between a `panic()` call and
   the next `main_loop` while-condition check still runs with the old
   `exit_reason`; `check_main_loop_stops()` explicitly documents one such
   race (targeted-mode depletion racing the fast-die ring) that required a
   dedicated early-detection branch to avoid a false corruption panic.
5. **No signal-handler races in this layer** — verified there is no
   SIGCHLD (or other) handler installed in the parent process; all reap
   and watchdog logic runs synchronously inside `main_loop`'s tick, so the
   classic async-signal-safety concerns for a fuzzer's process reaper do
   not apply here. The tradeoff is polling latency (up to one tick, plus
   the 25ms idle sleep) between a child dying and the parent noticing.

## Summary

main/ is the parent's control plane: `main_loop()` in main/loop.c sequences a
fixed per-tick pipeline (drain child-published state → check stop
conditions → run periodic surfaces → top up the fleet), main/spawn.c owns
fork/slot-allocation with layered backoff and forensic capture on failure,
main/reap.c owns poll-based reaping with a D-state-aware two-phase slot
lifecycle (live → zombie-pending → free) plus a stuck-child watchdog and
fork-die-respawn loop breaker, and main/stats.c renders the operator-facing
health/coverage summary at a throttled, change-gated cadence. The layer
touches nearly every other subsystem's periodic hook (kcov, cmp_hints,
minicorpus, stats, self_cgroup, canary queue) but owns none of their
internal state — it is purely the tick driver and process-lifecycle
authority.
