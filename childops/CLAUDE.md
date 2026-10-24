# childops/ — Scripted/stateful per-child fuzz workloads for Trinity

Trinity's default fuzzing loop (`random_syscall/`) picks one syscall in
isolation per iteration. Some kernel bug classes (UAF/refcount races,
teardown-vs-lookup races, multi-step object lifecycles) only surface when a
specific *sequence* of syscalls runs with real state threaded through it.
childops/ is where those scripted sequences live: each file implements one
"childop" — a self-contained C function, dispatched instead of a random
syscall for the current fork'd child, that drives a fixed or semi-fixed
sequence against one kernel subsystem/feature/race window.

The set is deliberately small. An earlier tree carried 168 dispatched ops;
runtime coverage data showed most of them producing no new edges over a full
run while the picker's dormant gate progressively starved them, so only the
ops with measured edge yield were kept. Adding one back is fine — the bar is
evidence that it reaches something the random-syscall path does not.

## Files

### Structural pattern

Each dispatched op is one `.c` file exporting a single
`bool <op>(struct childdata *)` entry point. Registration is by extern
symbol through the X-macro registry in `include/childop.def`, which expands
into the enum, the dispatch table, the name lookup, the outer-KCOV-bracket
eligibility switch, and the picker's slot/dormant-gate arrays. There is no
path coupling: the Makefile needs a glob line per directory, and a new op
needs a `childop.def` row.

## Notes

- The looping ops (`xattr_thrash`, `epoll_volatility`, `vsock_transport_churn`,
  `rxrpc_key_install`) bound themselves twice, by an iteration cap and a
  200 ms wall-clock budget, both well inside the `alarm(1)` that
  `child/child.c` arms around every alt-op, so a wedged kernel path still
  trips the stall detector.
- `vsock_transport_churn` forks (through `userns_run_in_ns()`). It is the
  membership of the canary picker's pid-heavy suppression set
  (`child/child-canary-policy.c`); anything else that grows an inner fork
  belongs there too.
