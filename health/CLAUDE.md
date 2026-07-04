# health/ — Signals, Crashes & Kernel-Health Monitoring

The layer that decides whether what just happened is a *finding* (a real kernel bug) or *noise* (an expected fuzzing side-effect), and assembles the evidence when it's a finding: signal handling + the child signal-mask policy, the pre-crash/breadcrumb rings that reconstruct what led to a fault, the `/dev/kmsg` scraper and taint-bit watch that catch kernel-side trouble, and the post-mortem dump assembly.

## Files (7 files, ~3,188 LOC)

| File | Lines | Role |
|---|---|---|
| signals.c | 1431 | Signal handling and the child signal-mask policy — installs handlers, classifies signals, drives the crash path. |
| post-mortem.c | 559 | Crash post-mortem dump assembly — gathers the syscall record, rings, and context into the crash report. |
| kmsg-monitor.c | 475 | Live `/dev/kmsg` scraper capturing kernel diagnostics before the taint bit flips; runs as a helper process outside the fuzz-child `pids[]` machinery. |
| pre_crash_ring.c | 246 | Per-child ring of recent syscalls, drained by the BUG path to recover the sequence that led to a crash. |
| breadcrumb_ring.c | 230 | Per-child breadcrumb ring for `post_handler_corrupt_ptr` fires. |
| taint.c | 172 | Kernel taint-bit checking — the first signal the kernel went sideways. |
| signals-safelist.c | 75 | The CHILD-NON-FATAL signal set derived from the signal-mask policy. |

## Key invariants
- **async-signal-safe handlers** — signal-handler bodies in `signals.c` may only call async-signal-safe libc or the trinity-internal `sigsafe_*` helpers (gated by `scripts/check-static/signal-handler-async-unsafe.sh`, which pins `health/signals.c`).
- **SIGALRM/SIGXCPU without SA_RESTART** — deliberately no SA_RESTART so a blocking syscall is interrupted rather than restarted; callers must not use bare `waitpid()` (gated by `no-bare-waitpid.sh`).
- **taint is ground truth** — a flipped kernel taint bit means the kernel went sideways; that's a finding regardless of the child's own signal disposition.
- **finding vs noise** — the signal-safelist plus the defense counters separate expected fuzz side-effects (guard-catches, rejected bad-frees) from real faults; only the latter become crash reports.

## Interactions
- Reads the syscall record from **`dispatch/`** and the child context from **`child/`** to build the pre-crash sequence.
- The `/dev/kmsg` + taint watch surface kernel-side faults that never raise a userspace signal.
- Crash reports feed the upload/triage pipeline downstream.
