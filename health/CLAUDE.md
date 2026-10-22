# health/ — Signals, Crashes & Kernel-Health Monitoring

The layer that decides whether what just happened is a *finding* (a real kernel bug) or *noise* (an expected fuzzing side-effect), and assembles the evidence when it's a finding: signal handling + the child signal-mask policy, the pre-crash/breadcrumb rings that reconstruct what led to a fault, the `/dev/kmsg` scraper and taint-bit watch that catch kernel-side trouble, and the post-mortem dump assembly.

## Files (11 .c files + 1 internal header, ~3,796 LOC)

| File | Lines | Role |
|---|---|---|
| signals-policy.c | 338 | Signal install/mask policy — `mask_signals_child()` and `setup_main_signals()`, watchdog handlers (SIGALRM/SIGXCPU), catch-all `sighandler`, the parent's SIGINT/SIGTERM stop handler. |
| signals-fault-handler.c | 676 | Child and main fault handlers — the M6 sigsetjmp site, `child_fault_handler()`, `main_fault_handler()`, beacon stamp, buglog redirect, guard-page attribution. |
| signals-precrash.c | 257 | Pre-crash capture — glibc `__abort_msg` capture, per-child stderr memfd, `open_buglog_and_drain_stderr()`. |
| signals-async-safe.c | 187 | Async-safe utilities — `write_siginfo_safely()`, `write_backtrace_raw_pcs()`, `fault_beacon_extract_{ip,sp}()`. |
| signals-internal.h | 115 | Private cross-file interface — `struct sigsafe_buf` + `sigsafe_*` inlines; forward decls for de-static'd helpers. |
| signals-safelist.c | 75 | The CHILD-NON-FATAL signal set derived from the signal-mask policy. |
| post-mortem.c | 626 | Crash post-mortem dump assembly — gathers the syscall record, rings, and context into the crash report. |
| kmsg-monitor.c | 537 | Live `/dev/kmsg` scraper capturing kernel diagnostics before the taint bit flips; runs as a helper process outside the fuzz-child `pids[]` machinery. |
| sysrq-lockup.c | 360 | Opt-in (`--sysrq-on-lockup`) wedge diagnostic — drives SysRq 'w' + 'l' to get the kernel's own blocked-task and all-CPU-backtrace dump when the fleet wedges. Called from `main/reap-watchdog.c`, short-circuited on the flag so a default run is byte-identical. |
| pre_crash_ring.c | 246 | Per-child ring of recent syscalls, drained by the BUG path to recover the sequence that led to a crash. |
| breadcrumb_ring.c | 231 | Per-child breadcrumb ring for `post_handler_corrupt_ptr` fires. |
| taint.c | 263 | Kernel taint-bit checking — the first signal the kernel went sideways. |

## Key invariants
- **async-signal-safe handlers** — signal-handler bodies in `signals-fault-handler.c` and `signals-policy.c` may only call async-signal-safe libc or the trinity-internal `sigsafe_*` helpers (gated by `scripts/check-static/signal-handler-async-unsafe.sh`, which discovers handlers from `signals-policy.c` and checks bodies across all `signals-*.c` files).
- **parent stop signals** — the parent stops only for an `SI_KERNEL` SIGINT (a terminal ctrl-c; a positive `POLL_*` code from `F_SETSIG` does not count) or an `SI_USER` SIGINT/SIGTERM whose `si_uid` no child can hold (`parent_stop_reason()`); every other stop signal is ignored as fuzz noise, and a stop never relabels a failure shutdown as clean (a child's own `exit_reason` writes still can). Children ignore SIGINT (`mask_signals_child()`): only the parent acts on a ctrl-c. See Documentation/signals.md.
- **parent fault signals** — `main_fault_handler()` re-raises only when `fault_signal_is_real()` calls the signal a real fault (`SI_KERNEL`, or a positive code on a signal with signal specific si_codes) or the parent's own `abort()`/`raise()` (`SI_TKILL`/`SI_USER` with its own pid); a `POLL_*` code on SIGABRT/SIGQUIT and `si_pid` under any other negative code are not evidence, and the F_SETSIG sanitiser routes a SIGIO only to a signal the parent ignores (`parent_ignores_sigio_as()`, checked against `setup_main_signals()` by `tests/parent_stop_test.c`). See Documentation/signals.md.
- **child fault signals** — `child_fault_handler()`, and the guard handlers in `mm/fault-read.c`, `mm/fault-write.c` and `childops/mm/pagecache-canary-check.c`, ask the same `fault_signal_is_real()` as the parent and trust `si_pid` only under `SI_USER`/`SI_TKILL`: a sibling's `rt_sigqueueinfo()` writes any `si_pid` under `SI_QUEUE`/`SI_MESGQ`/`SI_ASYNCIO` and a SIGIO's `si_band` reads as one, so those are ignored, and only an own-pid `SI_USER`/`SI_TKILL` inside `do_syscall()` is dropped quietly as the child's own fuzzing. `tests/child_fault_test.c` delivers each shape to a forked task, and to the two walkers in `mm/`. `writer_trap_handler()`, the `--writer-watch` SIGTRAP handler, asks the rule too, so a sibling's SIGTRAP and a SIGIO-routed one are ignored; it has no quiet drop, and a SIGTRAP the rule passes is reported and ends the child. See Documentation/signals.md.
- **SIGALRM/SIGXCPU without SA_RESTART** — deliberately no SA_RESTART so a blocking syscall is interrupted rather than restarted; callers must not use bare `waitpid()` (gated by `no-bare-waitpid.sh`).
- **taint is ground truth** — a flipped kernel taint bit means the kernel went sideways; that's a finding regardless of the child's own signal disposition.
- **finding vs noise** — the signal-safelist plus the defense counters separate expected fuzz side-effects (guard-catches, rejected bad-frees) from real faults; only the latter become crash reports.

## Interactions
- Reads the syscall record from **`dispatch/`** and the child context from **`child/`** to build the pre-crash sequence.
- The `/dev/kmsg` + taint watch surface kernel-side faults that never raise a userspace signal.
- Crash reports feed the upload/triage pipeline downstream.
