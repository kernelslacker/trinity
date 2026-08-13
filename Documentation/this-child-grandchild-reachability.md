# this_child() in fork()'d grandchildren — invariant vs per-process members

## Mechanism

`this_child()` returns the pointer stored in the thread-local `cached_pid`
slot.  That slot is populated once when the process is first identified as a
trinity child worker.  `fork()` copies the entire address space COW, including
the thread-local storage block, so `cached_pid` is **not** refreshed in a
grandchild.  The grandchild therefore continues to call `this_child()` and
receives the **parent's childdata slot** (non-NULL) rather than NULL.

Key consequence: any code path that calls `this_child()` inside a function
that may run in a fork()'d grandchild is accessing the **parent's** struct,
not one belonging to the grandchild.

## Member classification

| Category       | Members                                                     | Safe to read in grandchild? | Safe to write? |
|----------------|-------------------------------------------------------------|-----------------------------|----------------|
| FORK-INVARIANT | `op_type`, `op_nr`                                          | **Yes** — set before fork, never mutated | No (would corrupt parent) |
| PER-PROCESS    | `fault_beacon`, fd tables, `kcov.fd`, `syscall.*` fields,  | No                          | No             |
|                | `breadcrumb_ring`/`prop_ring` cursors, `cached_pid` itself  |                             |                |

Fork-invariant members are written exactly once (before the worker enters its
dispatch loop) and are never mutated again.  A grandchild reading them gets the
same value the parent would see, making the read safe for attribution purposes.

Per-process members track state that is meaningful only within the owning
process (open file descriptors, signal delivery state, ring buffer cursors,
etc.).  A grandchild reading or writing them through the COW-inherited slot
corrupts the parent's bookkeeping.

## Safe established pattern: reading op_type / op_nr

The canonical safe use is snapshotting `op_type` to attribute a direct syscall
count, in a function that may execute in a grandchild:

```c
/* qrtr-bind-race.c:169 */
struct childdata *tc = this_child();
const enum child_op_type op = tc ? tc->op_type : NR_CHILD_OP_TYPES;
if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
    childop_direct_syscalls_add(op, n);
```

```c
/* inet-listener-rehash-race.c:217 */
struct childdata *tc = this_child();
const enum child_op_type op = tc ? tc->op_type : NR_CHILD_OP_TYPES;
if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
    childop_direct_syscalls_add(op, n);
```

The bounds guard (`NR_CHILD_OP_TYPES`) is mandatory: it ensures the read is
treated as a no-op if something unexpected (e.g. a non-child process calling
`this_child()`) produces a stale value.

## Unsafe established pattern: writing per-process state through the COW slot

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

## Forward pointer

The check-static rule that flags `this_child()` combined with per-process
member accesses in grandchild-capable childops functions is implemented in
`scripts/check-static/childop-grandchild-this-child.sh`.
