# main/ — Parent Process Orchestration Layer

The Trinity parent process: the entry point (`trinity.c`) and CLI/tunable
parsing (`params/`), then the control plane that forks and tracks the fuzzer
child fleet, reaps exits, runs the D-state/stuck watchdog, and drives the
periodic stats/health dump. `trinity.c`'s `main()`/`epoch_loop()` sets up and
repeatedly calls `main_loop()`; none of this fuzzes anything itself.

## Files

| File | Role |
|---|---|
| trinity.c | Process entry: `main()`, option/table setup, and the epoch loop that repeatedly calls `main_loop()`. Does not fuzz. |
| trinity-warmstart.c | Startup/shutdown staging split out of `trinity.c`: `warm_start_all()`, `init_main_process()`/`init_main_early()`/`init_pre_fork()`, `persist_state_on_clean_exit()`, `run_oneshot_passes()`; `main/trinity-internal.h` holds the declarations the two files share |
| params/ | CLI option parsing and the global tunables/flags the rest of the codebase reads (targeting, `--childop`, richness levers). Split by concern -- see the subdirectory breakdown below. |
| main/loop.c | `main_loop()` driver: per-tick phase sequencing (drain → stop-checks → periodic surfaces → fork-replace), epoch reset (`reset_epoch_state`), `panic()` |
| main/reap.c | Reap core: `reap_child()`, `reap_dead_kids()` `waitpid(-1)` drain, `kill_all_kids()`, `get_pid_state()`, signal-status dispatch (`handle_children()`) |
| main/reap-watchdog.c | Stuck-child watchdog: `is_child_making_progress()`, SIGKILL escalation, stuck-fd eviction, wedge accounting, `stall_genocide()`, `check_children_progressing()` |
| main/reap-dstate.c | Bounded `/proc` readers for D-state forensics: wchan/stack/syscall/fdinfo dumps, epoll/select fd topology, `dstate_diag_budget_take()` diagnostic budget |
| main/reap-zombie.c | Deferred slot reuse until the kernel releases a D-state or stopped child: `register_zombie_slot()`, `process_zombie_pending()`, `find_free_childno()`, quarantine accounting |
| main/reap-fastdie.c | Fork-die-respawn busy-loop detector: `record_reap()` ring, `reap_entry_is_fast_die()`, `bail_fast_die_loop()` |
| main/reap-corruption.c | `shm_is_corrupt()`: op-count monotonicity, `shm_published` mirror page and pid sanity checks |
| main/spawn.c | `fork_children()`/`spawn_child()`: slot allocation, fork-failure backoff/bail, fork-pressure drain, forensic snapshots, final cross-run state save |
| main/stats.c | `print_stats()`: KCOV/CMP diagnostic lines, picker/plateau/pool-ratio dumps, per-op-count-delta throttling |

The `main/reap-*.c` family shares cluster-private declarations in
`main/reap-internal.h`; callers outside that family go through
`include/main-internal.h`.

### `main/params/` subdirectory

CLI parsing is split by concern so adding a knob only touches the file that
owns that knob's concern.  All
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
| `coverage.c` | KCOV/CMP/frontier/reach/blob/cmsg strategy knobs. |
| `childop.c` | Child-slot sizing (`-C`, `--alt-op-children`, `--explorer-children`) and the canary/fork-pressure knobs (`--canary-slots`, `--canary-window`, `--no-canary-queue`, `--canary-seed`, `--fork-pressure-drain`). |
| `debug.c` | writer-pin canary, `--guard-shared`, verbosity/diagnostics, `-h`/`-L`/`-I`/`-b` info commands, misc long-only flags. |
| `compat.c` | Backwards-compat parser helpers: `--redqueen-pending-pick` name/parser pair and the `enable_disable_fd_usage()` hook `usage()` calls. |

Roles split by verb: main/loop.c is the loop, main/spawn.c forks, the
main/reap-*.c family reaps/watches, main/stats.c prints. They share
parent-private state declared in `include/main-internal.h` (`pidstatfiles`,
`zombie_pids`, `zombie_since`, `spawn_times`, `hiscore`, `stall_count`) —
this header is the internal seam for the main/loop.c split, not a public
API surface.

## Process lifecycle

- **Slot model**: `max_children` fixed-size slots, indexed by `childno`,
  backed by `pids[]` in shm and `children[]` (childdata) also in shm.
  `spawn_child()` forks via `self_cgroup_fork_into_workload()`, writes
  `pids[childno]` last (release store) so the child spins in `init_child()`
  until its own pid is visible.
- **No SIGCHLD handler**: reaping is pure polling. Each tick
  `handle_children()` drains with `waitpid(-1, WNOHANG)` in a bounded loop
  (cap 64), because SIGCHLD is edge-triggered and a per-slot `waitpid()`
  walk can fall behind when multiple children die in one tick.
  `reap_dead_kids()`, the housekeeping and shutdown path, runs the same
  drain and then a second pass for slots the drain's bookkeeping missed: it
  asks the slot's `/proc/<pid>/stat` fd, opened at spawn and so pinned to
  the task rather than the pid number, whether the task is gone, and falls
  back to `kill(pid, 0)`+ESRCH only for a slot with no fd. Any other
  `kill()` errno is logged and leaves the slot alone.
- **Two-tier dead-slot handling**: a normally-exiting/signaled child goes
  through `reap_child()` immediately (clears `pids[i]`, decrements
  `running_childs`, tears down pre-crash ring / bug-backtrace / fault
  beacon). A child the kernel has not released yet — stuck in D-state,
  or stopped — cannot be reaped safely: its task struct can still write
  into childdata after the slot looks empty. So it's parked in
  `zombie_pids[]`/`zombie_since[]` via `register_zombie_slot()` and only
  handed back to `find_free_childno()` once a later `waitpid(WNOHANG)` in
  `process_zombie_pending()` confirms the kernel actually released it.
  If `ZOMBIE_REAP_TIMEOUT_SEC` (300s) runs out first, the slot is
  quarantined instead: out of service for the rest of the run, and
  counted toward the `EXIT_KERNEL_STUCK` threshold.
- **Stuck-child escalation**: `is_child_making_progress()` compares
  `child->tp` (last progress timestamp) each tick; at 30s idle it dumps a
  D-state diagnostic snapshot (wchan/stack/fdinfo, epoll/select fd topology)
  once and sends SIGKILL, then evicts the fds the stuck syscall held from
  the object pool, with or without `-D` (the in-child alarm eviction never
  ran for a wedge that got this far). Removing the object closes the
  parent's copy, and `close()` calls the file's `->flush` (FUSE, NFS and
  CIFS flush through the server), so the eviction runs after the kill and is
  skipped for a task in D state, which `-D` says. If still alive at 40s it
  repeats SIGKILL every tick. `kill_count >= 10` routes the slot into
  zombie-pending regardless of D/S state, since SIGKILL cannot preempt
  D-state. If every running child is simultaneously stalled,
  `stall_genocide()` randomly SIGKILLs ~1/4 of the fleet to break a
  fleet-wide wedge.
- **Pacing**: no sleep-based pacing in the steady state — `handle_children()`
  returns the drain count and `main_loop()` only ppoll()s (25 ms timeout,
  cgroup memory.events inotify fd for early wake) when the tick reaped
  nothing. Fork storms
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
  next pass), the operator stop file (`trinity-stop` in
  `trinity_tmpdir_abs()`, cleared at startup by `stop_file_init()`), and
  drains locks held by now-dead children.
- **Fast-die loop detector**: `record_reap()` keeps a 16-entry ring of
  recent reap outcomes; if all 16 are "died within 2s, non-zero exit"
  it declares a fork-die-respawn busy-loop (symptomatic of shm corruption
  making every fresh child immediately trip a startup check) and panics
  `EXIT_SHM_CORRUPTION`. Several `exit_reason` values (clean targeted-mode
  exits, SIGINT, epoch/count-reached) are explicitly excluded from
  counting as fast-die so legitimate rapid clean shutdowns don't
  false-positive this detector.

## Key design decisions

1. **Poll, don't trap** — SIGCHLD has no handler in the parent
   (`setup_main_signals()` leaves it at `SIG_DFL`); all reaping is
   `waitpid(WNOHANG)` polling from `main_loop`'s tick. This sidesteps
   async-signal-safety entirely for the reap path at the cost of
   edge-triggered-signal loss, which is why the drain uses `waitpid(-1)`
   rather than one pid at a time.
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
   It also leaves parked slots parked, childdata untouched, since the
   boundary proves nothing about their tasks: `process_zombie_pending()`
   retires a zombie-pending slot next epoch, and a quarantined slot stays
   out of service for the run and keeps counting toward the
   `EXIT_KERNEL_STUCK` threshold. The reset begins with a compare-exchange
   of `exit_reason` from `EXIT_EPOCH_DONE`; if a stop signal replaced the
   reason after `epoch_loop()` read it, the reset returns false having
   touched nothing and the loop ends the run.
4. **`panic()` is a deferred, non-blocking stop signal** — it only stamps
   `shm->spawn_no_more`/`shm->exit_reason`; the actual unwind happens on
   the main_loop while-condition's next check, giving in-flight per-tick
   work (drain, watchdog kill) one more pass to run cleanly before the
   loop exits.
5. **Bounded backoff everywhere in the spawn path** — per-slot retry cap
   (10; `fork_children()` then skips the slot for the rest of the call and
   the next call retries it, so a slot that will not fork does not hold
   the startup barrier shut) and a cumulative per-`fork_children()`-call
   backoff cap (2s, about 117 failed attempts at 10-20ms each) that yields
   back to `main_loop` mid-refill so reap/watchdog aren't starved during a
   sustained fork-pressure episode.  That backoff cap is what bounds a
   call: the per-call 1000-failure `EXIT_FORK_FAILURE` bail is never
   reached behind it, and a fleet that cannot fork is retried every tick.
   The opt-in fork-pressure drain counts failures across calls, so a
   refill of a few slots still reaches its threshold of 100.  The 2s cap
   fits eleven skips, so under a global fork cap (RLIMIT_NPROC, cgroup
   `pids.max`) a startup fill with twelve or more slots failing never
   skips them all; once its spawns have failed for 5s straight
   (`SPAWN_STALL_OPEN_S`, timed across calls and restarted by a
   `fork_children()` spawn that succeeds and by the epoch reset) it
   opens the barrier anyway and logs once.  A failed spawn that is really
   the run stopping (`spawn_child()` panics `EXIT_NO_FDS` near the fd
   limit or when `get_num_fds()` fails with EMFILE or ENFILE, as it does
   once the fds run out, or `exit_reason` / `spawn_no_more` is set
   mid-retry) ends both retry loops at once, uncounted, instead of being
   retried as a fork failure, and both loops check again after each
   backoff sleep, so a stop that lands mid-sleep forks nothing further.
   Any other `get_num_fds()` failure only skips that spawn's headroom
   check, and is logged once per run.
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

- `trinity.c` / `trinity-warmstart.c` — top-level caller: `warm_start_all()` before entry,
  `epoch_loop()`/direct `main_loop()` call, `persist_state_on_clean_exit()`
  mirrors `final_state_save()`'s save set on the clean-exit path.
- `child/child.c` / `child/child-init-*.c` — `spawn_child()` forks into `child_process()`
  (child/child.c); child startup blocks in `init_child()` until the parent
  publishes `pids[childno]`.
- `shm.h` / shared childdata (`children[]`, `pids[]`) — the entire slot
  model; `shm->running_childs`, `shm->exit_reason`, `shm->spawn_no_more`,
  `shm->ready` are the cross-process coordination fields.
- `main/stats.c`, `stats/stats-ring.c`, `stats/periodic/`, `stats/runid.c` — per-tick
  ring drain (`stats_ring_drain_all`), periodic dump helpers called from
  `run_periodic_surfaces()`, run-identity snapshot at loop entry.
- `kcov.h`, `kcov/plateau.c`, `kcov/persist.c` — `kcov_plateau_check()`,
  `kcov_bitmap_maybe_snapshot()`/`kcov_bitmap_canary_check()`,
  KCOV CMP/PC diagnostic formatting consumed by main/stats.c.
- `cmp_hints/cmp_hints.c`, `cmp_hints/persist.c` — `cmp_hints_maybe_snapshot()`
  each tick; `final_state_save()` calls `cmp_hints_save_file()` on the
  fork-failure bail path.
- `persist/minicorpus-*.c` — `minicorpus_mut_attrib_canary_check()`,
  `minicorpus_save_file()` in `final_state_save()`, chain-corpus snapshot
  trigger (`chain_corpus_maybe_snapshot()`).
- `utils/self_cgroup_*.c` — `self_cgroup_events_fd()` exposes the memory.events
  inotify fd for `main_loop()`'s ppoll idle-wait; `self_cgroup_events_check()`
  runs on POLLIN to drain the notification and update the fork throttle;
  `self_cgroup_fork_into_workload()` performs the actual fork; memory.high
  back-pressure feeds `fork_throttle_us`.
- `child/child-canary-*.c` / canary queue — `canary_queue_init()`,
  `canary_queue_on_child_respawn()`, `canary_queue_on_crash()`,
  `canary_queue_tick()`, `fork_pressure_drain_active()` consumed by the
  canary picker to suppress pid-heavy ops during fork pressure.
- `child/child-altop-pick.c` — `init_altop_dispatch()`/`assign_dedicated_alt_op()` for
  dedicated-alt-op child slots.
- `rand/seed.c` — `reseed()` on every replacement spawn after startup and on epoch reset.
- `utils/locks.c` — `check_all_locks()`/`force_bust_lock()` for lock recovery
  after a child dies holding the syscall dispatch lock.
- `dispatch/pids.c` / `pid_is_valid`/`pid_alive`/`kill_pid` — pid-liveness and
  signal-delivery primitives used throughout reap/spawn.
- `health/kmsg-monitor.c` — `kmsg_monitor_note_reaped()` notified when
  `reap_dead_kids()` reaps an untracked pid, in case it was the kmsg
  helper process (which lives outside the fuzz-child `pids[]` machinery).

## Areas of attention

1. **The reap cluster's responsibility span** (6 files, ~2,700 LOC) — shm
   corruption sanity, normal reap, zombie/D-state deferral, watchdog
   escalation, D-state forensic dumping (5 separate bounded `/proc` readers),
   fast-die-loop ring detection, and signal-status dispatch. Each now has its
   own translation unit, so a change to one sub-concern (e.g. the D-state
   diagnostic format) lands in one file; what crosses the boundary is
   declared in `main/reap-internal.h`. The largest files in main/ are
   `spawn.c` (863), `loop.c` (844) and `reap-watchdog.c` (807).
2. **Slot-reuse correctness is load-bearing and documented but easy to
   violate on a future edit** — `find_free_childno()`'s double-empty check
   (`pids[i]` AND `zombie_pids[i]`) is the sole guard against the
   documented D-state-write-after-reap corruption case; any new code path
   that reaps a slot without going through `reap_child()` +
   `register_zombie_slot()`'s logic would reopen that hole.
3. **`bail_fast_die_loop()`'s exclusion list is a maintenance trap** —
   `reap_entry_is_fast_die()` treats two `exit_reason` values in any mode,
   and the `exit_reason_is_clean()` set (include/exit.h) in targeted mode,
   as "expected fast clean exit, don't count toward the corruption ring."
   That predicate also picks the exit code and gates the end-of-run
   warm-start saves, so a new clean shutdown reason goes there.  Any other
   exit path that legitimately exits quickly (new targeted-mode depletion
   path) must remember to add itself here or risk a false-positive
   `EXIT_SHM_CORRUPTION` panic under adversarial timing.
4. **`panic()`'s deferred-effect design means every caller must reason
   about one extra tick of execution** — code between a `panic()` call and
   the next `main_loop` while-condition check still runs with the old
   `exit_reason`; `check_main_loop_stops()` explicitly documents one such
   race (targeted-mode depletion racing the fast-die ring) that required a
   dedicated early-detection branch to avoid a false corruption panic.
5. **No signal-handler races in this layer** — `setup_main_signals()`
   installs two handlers in the parent, and neither touches reap or
   watchdog state. `main_stop_handler` (SIGINT/SIGTERM) only decides a
   stop reason and calls `panic()`, two atomic stores, so its effect
   arrives as one more deferred stop (Key design decision 4).
   `main_fault_handler` (the fault signals) reports a real fault and
   re-raises it, and ignores one a child sent. SIGCHLD stays at
   `SIG_DFL`, and the signals children can send the parent (SIGHUP,
   SIGUSR1/2, SIGALRM, SIGPIPE, the RT range, ...) are ignored. All reap
   and watchdog logic runs synchronously inside `main_loop`'s tick, so
   the classic async-signal-safety concerns for a fuzzer's process reaper
   do not apply here. The tradeoff is polling latency (up to one tick,
   plus the 25ms idle sleep) between a child dying and the parent
   noticing.

## Summary

main/ is the parent's control plane: `main_loop()` in main/loop.c sequences a
fixed per-tick pipeline (drain child-published state → check stop
conditions → run periodic surfaces → top up the fleet), main/spawn.c owns
fork/slot-allocation with layered backoff and forensic capture on failure,
the main/reap-*.c family owns poll-based reaping with a D-state-aware two-phase slot
lifecycle (live → zombie-pending → free) plus a stuck-child watchdog and
fork-die-respawn loop breaker, and main/stats.c renders the operator-facing
health/coverage summary at a throttled, change-gated cadence. The layer
touches nearly every other subsystem's periodic hook (kcov, cmp_hints,
minicorpus, stats, self_cgroup, canary queue) but owns none of their
internal state — it is purely the tick driver and process-lifecycle
authority.
