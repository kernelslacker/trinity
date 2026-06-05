#pragma once

#include <stdbool.h>
#include <sys/types.h>

/*
 * Self-cgroup: at startup, place trinity into its own cgroup v2 sub-cgroup
 * with a memory cap so a runaway allocation triggers a scoped OOM kill of
 * the worker pool instead of a host-wide global OOM (which would take down
 * the surrounding shell/tmux/ssh) or an upstream group-OOM cascade (which
 * would take down trinity-main alongside the workers).
 *
 * Layout (preferred, "split mode"):
 *
 *   trinity-<pid>/                 container, no procs
 *     ├── parent/                  trinity-main lives here
 *     │                            memory.high small reservation, no .max,
 *     │                            memory.oom.group=0 — never the OOM victim
 *     └── children/                all forked workers live here
 *                                  memory.max=<cap>, memory.oom.group=1 —
 *                                  cap kills the whole worker pool atomically,
 *                                  parent then re-spawns from clean state
 *
 * Workers land in children/ via clone3(CLONE_INTO_CGROUP) so the placement
 * is atomic (no transient window in parent/ where a racing allocation
 * could land against the wrong limit).  See self_cgroup_fork_into_workload().
 *
 * Setup also arms an inotify watch on children/memory.events so the parent
 * can apply proactive back-pressure on memory.high crossings (fork-rate
 * throttle).  memory.max crossings are tracked for diagnostics only — the
 * kernel's group-OOM handles the cap.  Polled from the parent's main_loop
 * via self_cgroup_events_check().
 *
 * Failures degrade gracefully: if the parent/children split can't be set
 * up (older kernel without memory.oom.group, delegation gap, etc.) trinity
 * falls back to a single-cgroup with memory.max — the operator still gets
 * the hard cap, just without OOM scope isolation.  When even that fails
 * trinity continues without any cgroup containment rather than refusing
 * to start.
 */
void self_cgroup_setup(void);
void self_cgroup_cleanup(void);
void self_cgroup_events_check(void);

/*
 * fork() replacement that places the new child in the children/ cgroup
 * via clone3(CLONE_INTO_CGROUP).  Same return semantics as fork(): pid in
 * parent, 0 in child, -1 on error.  Falls back to plain fork() (single-
 * cgroup mode or no cgroup at all) or to fork()+post-migrate (older
 * kernel with no clone3) when CLONE_INTO_CGROUP isn't available.  Called
 * by spawn_child() in main.c as a drop-in replacement for fork().
 */
pid_t self_cgroup_fork_into_workload(void);

/*
 * Per-spawn fork delay applied by the parent before each fork().  Set
 * by self_cgroup_events_check() in response to memory.high bumps and
 * decayed back to 0 after a quiet streak.  Read once per spawn from
 * spawn_child(); 0 means no throttle (the common case).
 */
extern unsigned int fork_throttle_us;

/*
 * Syntactic validation of a --memory-max / --memory-high /
 * --memory-swap-max argument.  Called from parse_args() so --dry-run
 * exercises the same acceptance rules as a live run -- the historical
 * validator lived inside self_cgroup_setup() which is skipped under
 * --dry-run, letting dry-run report success on inputs the real run
 * would reject.  Accepts "max", "<n>%" with 1 <= n <= 100, and
 * "<n>[KMG]" decimal byte counts; rejects leading signs, empty input,
 * unknown suffixes, percentage out-of-range, and overflow.  Emits a
 * "--flag: invalid memory-size ..." diagnostic on rejection.
 */
bool validate_cgroup_size_arg(const char *flag_name, const char *arg);
