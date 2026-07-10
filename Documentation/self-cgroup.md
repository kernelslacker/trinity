# Self-cgroup design notes

Companion to `include/self_cgroup.h` and `self_cgroup.c`.  The header
keeps the per-function contracts (load-bearing fd / inheritance
semantics stay next to the declarations); this document holds the
top-level design essay: what the cgroup layer buys us, the "split
mode" layout diagram, and the fallback history when a rung of the
layout isn't available.

## What it buys us

At startup, place trinity into its own cgroup v2 sub-cgroup with a
memory cap so a runaway allocation triggers a scoped OOM kill of the
worker pool instead of:

- a host-wide global OOM, which would take down the surrounding
  shell/tmux/ssh; or
- an upstream group-OOM cascade, which would take down trinity-main
  alongside the workers.

Both failure modes are recurrent on fuzz hosts once memory pressure
crosses the tail; the split-mode layout below is the shape that
survives them.

## Split-mode layout (preferred)

    trinity-<pid>/                 container, no procs
      ├── parent/                  trinity-main lives here
      │                            memory.high small reservation, no .max,
      │                            memory.oom.group=0 — never the OOM victim
      └── children/                all forked workers live here
                                   memory.max=<cap>, memory.oom.group=1 —
                                   cap kills the whole worker pool atomically,
                                   parent then re-spawns from clean state

Workers land in `children/` via `clone3(CLONE_INTO_CGROUP)` so the
placement is atomic (no transient window in `parent/` where a racing
allocation could land against the wrong limit).  See
`self_cgroup_fork_into_workload()`.

Setup also arms an inotify watch on `children/memory.events` so the
parent can apply proactive back-pressure on `memory.high` crossings
(fork-rate throttle).  `memory.max` crossings are tracked for
diagnostics only -- the kernel's group-OOM handles the cap.  Polled
from the parent's main loop via `self_cgroup_events_check()`.

## Failure fallback ladder

Failures degrade gracefully:

1. If the parent/children split can't be set up (older kernel without
   `memory.oom.group`, delegation gap, etc.) trinity falls back to a
   single-cgroup with `memory.max` -- the operator still gets the
   hard cap, just without OOM scope isolation.
2. When even that fails trinity continues without any cgroup
   containment rather than refusing to start.  Losing the cap is
   preferable to losing the run.

The header's `validate_cgroup_size_arg()` catches malformed
`--memory-max` / `--memory-high` / `--memory-swap-max` values at
parse time, before setup runs, so a bad argument aborts before any
fork/fuzz work has started.
