# Cgroup and startup-isolation options

Companion to `main/params/help.c` and `self_cgroup.c`.  Trinity
carves a self-cgroup at startup and puts the child fleet under its
own memory limits so a runaway worker cannot OOM the parent (which
is the process holding all the fuzzing state).  These options tune
that containment or opt out of it.  The `--help` output carries only
a one-line contract per option; the split between children and
parent reservations lives here.

Every memory option accepts three spellings:

- `max`  -- no cap
- `N%`   -- percent of `MemTotal`
- `N[KMG]` -- absolute bytes with a K / M / G suffix

## --memory-high

`children/memory.high` back-pressure threshold (workers cgroup).
Soft limit -- crossing it stalls the offending worker with reclaim
pressure but does not OOM it.  Default: 50%.

## --memory-max

Total trinity memory budget.  Split into
`children/memory.max = <this> - parent_high` and a small parent
reservation:

    parent_high = min(200M, this / 16)

so worker OOM does not take the parent.  Hard limit -- exceeding it
OOM-kills the offending worker.  Default: 60%.

## --memory-swap-max

`children/memory.swap.max` cap (workers cgroup).  Bounds the swap
Trinity's workers may consume; keeps a runaway allocator from
thrashing the host.  Default: 20%.

## --no-cgroup

Skip self-cgroup creation entirely.  No in-binary memory
containment; a runaway worker can OOM the parent and take the whole
run with it.  Use only when the host is providing containment (for
example, when Trinity is already running inside a systemd scope with
its own limits).

## --no-startup-isolation

Skip the parent-side `unshare(CLONE_NEWNET|CLONE_NEWNS)` +
`MS_PRIVATE` remount that the root-launched fuzzer does in
`init_pre_fork()`.  Children still take the per-child unshare path.
Default off; non-root runs never attempt parent-side isolation
regardless.
