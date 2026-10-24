# health/ — Signals, Crashes & Kernel-Health Monitoring

The layer that decides whether what just happened is a *finding* (a real kernel bug) or *noise* (an expected fuzzing side-effect), and assembles the evidence when it's a finding: signal handling + the child signal-mask policy, the pre-crash/breadcrumb rings that reconstruct what led to a fault, the `/dev/kmsg` scraper and taint-bit watch that catch kernel-side trouble, and the post-mortem dump assembly.

## Files

| File | Role |
|---|---|
| post-mortem.c | Crash post-mortem dump assembly — gathers the syscall record, rings, and context into the crash report. |
| taint.c | Kernel taint-bit checking — the first signal the kernel went sideways. |

## Key invariants
- **async-signal-safe handlers** — signal-handler bodies in `signals-fault-handler.c` and `signals-policy.c` may only call async-signal-safe libc or the trinity-internal `sigsafe_*` helpers (gated by `scripts/check-static/signal-handler-async-unsafe.sh`, which discovers handlers from `signals-policy.c` and checks their bodies in `signals-policy.c`, `signals-fault-handler.c`, `signals-async-safe.c` and `signals-precrash.c`).
- **parent stop signals** — the parent stops only for an `SI_KERNEL` SIGINT (a terminal ctrl-c; a positive `POLL_*` code from `F_SETSIG` does not count) or an `SI_USER` SIGINT/SIGTERM whose `si_uid` no child can hold (`parent_stop_reason()`); every other stop signal is ignored as fuzz noise, and a stop never relabels a failure shutdown as clean (a child's own `exit_reason` writes still can). Children ignore SIGINT (`mask_signals_child()`): only the parent acts on a ctrl-c. See Documentation/signals.md.
- **parent fault signals** — `main_fault_handler()` re-raises only when `fault_signal_is_real()` calls the signal a real fault (`SI_KERNEL`, or a positive code on a signal with signal specific si_codes) or the parent's own `abort()`/`raise()` (`SI_TKILL`/`SI_USER` with its own pid); a `POLL_*` code on SIGABRT/SIGQUIT and `si_pid` under any other negative code are not evidence, and the F_SETSIG sanitiser routes a SIGIO only to a signal the parent ignores (`parent_ignores_sigio_as()`, checked against `setup_main_signals()` by `tests/parent_stop_test.c`, and applied again at dispatch by `validate_arg_coupling()`). See Documentation/signals.md.
- **child fault signals** — `child_fault_handler()`, and the guard handlers in `mm/fault-read.c`, `mm/fault-write.c` and `childops/mm/pagecache-canary-check.c`, ask the same `fault_signal_is_real()` as the parent and trust `si_pid` only under `SI_USER`/`SI_TKILL`: a sibling's `rt_sigqueueinfo()` writes any `si_pid` under `SI_QUEUE`/`SI_MESGQ`/`SI_ASYNCIO` and a SIGIO's `si_band` reads as one, so those are ignored, and only an own-pid `SI_USER`/`SI_TKILL` inside `do_syscall()` is dropped quietly as the child's own fuzzing. `tests/child_fault_test.c` delivers each shape to a forked task, and to the two walkers in `mm/`. `writer_trap_handler()`, the `--writer-watch` SIGTRAP handler, asks the rule too, so a sibling's SIGTRAP and a SIGIO-routed one are ignored; it has no quiet drop, and a SIGTRAP the rule passes is reported and ends the child. See Documentation/signals.md.
- **SIGALRM/SIGXCPU without SA_RESTART** — deliberately no SA_RESTART so a blocking syscall is interrupted rather than restarted; callers must not use bare `waitpid()` (gated by `no-bare-waitpid.sh`).
- **taint is ground truth** — a flipped kernel taint bit means the kernel went sideways; that's a finding regardless of the child's own signal disposition.
- **finding vs noise** — the signal-safelist plus the defense counters separate expected fuzz side-effects (guard-catches, rejected bad-frees) from real faults; only the latter become crash reports.

## Interactions
- Reads the syscall record from **`dispatch/`** and the child context from **`child/`** to build the pre-crash sequence.
- The `/dev/kmsg` + taint watch surface kernel-side faults that never raise a userspace signal.
- Crash reports feed the upload/triage pipeline downstream.
