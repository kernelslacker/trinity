# child/ — Child Runtime Loop

Each forked child's per-iteration lifecycle: bring-up + sandbox, then the loop that runs one workload per iteration — either a random syscall (`random_syscall/`) or a scripted childop (`childops/`) via the alt-op picker — under an `alarm()` backstop and a set of self-integrity oracles. Distinct from `childops/`: those are the scripted *workloads*; this is the runtime *infrastructure* that drives them.

## Files

| File | Role |
|---|---|
| child-pidns-init.c | `start_pidns_init()`: the idle init that holds pid 1 of a pid namespace the child unshared, so the namespace outlives the child's first fork into it. No exit signal and its own process group keep it out of most of the child's waits, and `validate_arg_coupling()` makes the rest, a wait for any child with `__WALL`/`__WCLONE`, WNOHANG while `pidns_init_pid` is set; default signal dispositions leave it deaf to fuzzed signals bar SIGKILL/SIGSTOP; PDEATHSIG plus the child's pidfd end it with the child. A clone that still fails after a few tries leaves the child without an init. `pidns_init_lost()` has the child loop recycle the child on the 16-op tick once the init has died, since every fork would fail from then on. The sandbox also records where the child's forks land (`pidns_note_fork_target()`); an EXTRA_FORK fork that fails with ENOMEM after a fuzzed `unshare(CLONE_NEWPID)`/`setns()` moved them elsewhere counts as a lost init too (`pidns_note_fork_enomem()`), while an ENOMEM where the sandbox left them (memory pressure, make-it-fail) does not. |

## Key invariants
- **`alarm()` backstop** — every child arms an alarm so an indefinite-blocking syscall can't wedge it (paired with the per-syscall `NEED_ALARM` flag).
- **PDEATHSIG + getppid recheck** — arm `PR_SET_PDEATHSIG`, then re-check `getppid()` to close the parent-died-before-prctl race (`child_process()` in `child.c`). A root run arms again, and re-checks, right after `drop_privs()` in `init_child_setup_sandbox()`: `commit_creds()` zeroes `pdeath_signal` when the euid or egid changes.
- **Cap-drop verified, not assumed** — `child-capdrop-oracle.c` asserts the empty cap set; a child that failed to drop is a bug, not a fuzz finding.
- **Child stdio is isolated** — `child-init-isolate.c` points fd 0/1/2 at `/dev/null` so a fuzzed `write`/`splice`/`sendfile` cannot reach the operator's terminal, and `init_child()` then re-points stderr at an anonymous memfd (`init_stderr_memfd()`, `health/signals-precrash.c`) that the fault handler drains into the per-pid bug log on a real crash. Child-side `output()`/`outputerr()` text reaches a log only that way.

## Areas of attention
- Alt-op scoring / canary-promotion cadence live here; the *workloads* live in `childops/`.
- Signal-mask policy is in `health/signals-policy.c`, NOT here.
