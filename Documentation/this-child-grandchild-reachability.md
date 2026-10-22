# this_child() in fork()'d grandchildren — invariant vs per-process members

## Mechanism

`this_child()` (`dispatch/pids.c`) returns the `childdata` pointer cached in
the process-global `cached_child`, as long as `cached_pid` equals `mypid()`.
The cache (`cached_childno`, `cached_pid`, `cached_child`) is filled once per
worker by `set_child_cache()`, called from `init_child()`.  `fork()` copies the
address space COW, so the cache is **not** refreshed in a grandchild: `mypid()`
still returns the worker's pid, `this_child()` takes the fast path, and the
grandchild receives the **parent's childdata slot** (non-NULL) rather than
NULL.

Key consequence: any code path that calls `this_child()` inside a function
that may run in a fork()'d grandchild is accessing the **parent's** struct,
not one belonging to the grandchild.  The slot lives in shared memory, so the
grandchild's reads see live worker state and its writes land in the worker's
record.

## Member classification

| Category       | Members                                                     | Safe to read in grandchild? | Safe to write? |
|----------------|-------------------------------------------------------------|-----------------------------|----------------|
| FORK-INVARIANT | `op_type`, `op_nr`                                          | **Yes** — stable while the op body runs | No (would corrupt parent) |
| PER-PROCESS    | `fault_beacon`, fd tables, `kcov.fd`, `syscall.*` fields,  | No                          | No             |
|                | `breadcrumb_ring`/`prop_ring` cursors, `cached_pid` itself  |                             |                |

Fork-invariant members are written by the worker once per loop iteration,
before the childop body runs, and not again until that body returns.  A
grandchild reading them inside that window gets the same value the parent would
see, making the read safe for attribution purposes.

Per-process members track state that is meaningful only within the owning
process (open file descriptors, signal delivery state, ring buffer cursors,
etc.).  A grandchild reading or writing them through the COW-inherited slot
corrupts the parent's bookkeeping.

## Safe pattern: reading op_type / op_nr

The canonical safe use is snapshotting `op_type` to attribute a direct syscall
count, in a function that may execute in a grandchild:

```c
struct childdata *tc = this_child();
const enum child_op_type op = tc ? tc->op_type : NR_CHILD_OP_TYPES;
if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
    childop_direct_syscalls_add(op, n);
```

The bounds guard (`NR_CHILD_OP_TYPES`) is mandatory: it ensures the read is
treated as a no-op if something unexpected (e.g. a non-child process calling
`this_child()`) produces a stale value.  No childop in the tree uses this
snapshot today: `vsock-transport-churn.c` keeps the grandchild's tally on its
stack and lets the worker report its own.

## Unsafe pattern: writing per-process state through the COW slot

Any write to a per-process member — including stamping `fault_beacon`, updating
`kcov.fd`, or advancing ring cursors — through the COW-inherited slot corrupts
the parent worker.  The fault handler detects grandchildren with a write-free
predicate:

```c
/* health/signals-fault-handler.c */
if (mypid() != getpid()) {
    /* skip fault_beacon stamp — this_child() points at parent's slot */
    ...
}
```

`mypid()` returns `cached_pid`, which is written in the parent by `main()` and
in each forked primary child by `init_child()`.  Grandchildren never call
`init_child()`, so they inherit the parent's `cached_pid` unchanged.  Thus
`mypid() != getpid()` is TRUE in every grandchild and FALSE in every primary
child, with no marking required at fork sites.

## Enforcement

No check-static gate covers this rule.  Code that runs in a grandchild
(`do_extrafork()`, the `userns_run_in_ns()` callbacks) must keep per-process
members out of its `this_child()` accesses by review.
