#pragma once

#include <sys/types.h>
#include "child-api.h"
#include "types.h"

extern pid_t *pids;
extern pid_t mainpid;
extern pid_t cached_pid;
/*
 * Own start_time from /proc/<self>/stat field 22, cached at process
 * start (parent in main, child in set_child_cache).  The lock acquire
 * path stamps this into lk->owner_start_time so force_bust_lock can
 * detect pid recycles: a recycled pid will have a different start_time
 * even if its numeric pid matches the dead lock-owner's.
 */
extern unsigned long long cached_start_time;

/*
 * Cached self pid.  glibc 2.25 (2017) dropped its libc-side getpid()
 * cache to close a fork() race, so every libc getpid() call is now a
 * real syscall.  Profiling showed __getpid as the dominant inclusive
 * cost during fuzz runs; cache the result ourselves and route every
 * caller through this inline accessor.
 *
 * Storage is `cached_pid` (declared above), which already carries the
 * "this process's own pid" semantic: written in the parent right after
 * `mainpid = getpid()` in main(), and overwritten in each forked child
 * by set_child_cache() called from init_child() before any fuzz work
 * begins.  No thread-local storage is needed because trinity children
 * are processes (fork), not threads — each child gets its own private
 * copy of the global via copy-on-write.
 */
static inline pid_t mypid(void)
{
	return cached_pid;
}

#define for_each_child(i)	for (i = 0; i < max_children; i++)

#define CHILD_NOT_FOUND -1
#define EMPTY_PIDSLOT -1

bool pid_alive(pid_t pid);
unsigned long long pid_start_time(pid_t pid);
int find_childno(pid_t pid);
void set_child_cache(int childno, pid_t pid, struct childdata *child);
bool pidmap_empty(void);
void dump_childnos(void);
void dump_pids_page_state(void);
int pid_is_valid(pid_t);
void pids_init(void);

/*
 * CHILDOP_ARM_EFFECTIVE(op, arm)
 *
 * Atomically increment shm->stats.op.arm_effective_##arm.  Companion to
 * CHILDOP_ARM_ENTER (include/arm-tracking.h): whereas ARM_ENTER fires at
 * the top of each dispatch arm (entry into the arm), ARM_EFFECTIVE fires
 * when the arm produces its first observable output -- a successful syscall,
 * a non-error return, or any detectable side-effect the arm is supposed to
 * exercise.
 *
 * An arm where arm_entered > 0 but arm_effective == 0 ran but produced no
 * output (the 510-H class: config-dead past the arm entry point, a silent
 * uapi-value-wrong, or setup-gated at a sub-arm level).  The drain-time
 * check in dump_stats_dead_arm_check() (stats/dump/subsystems.c) logs a
 * RAN_NO_EFFECT entry for this condition.
 *
 * This macro is OPTIONAL.  Childops that do not call it simply have no
 * arm_effective data; they are not checked for the ran-but-did-nothing
 * condition.  To instrument a childop arm:
 *
 *   1. Add `unsigned long arm_effective_<arm>;` to the subsystem stats
 *      struct in stats/subsys/<childop>.h (alongside arm_entered_<arm>).
 *   2. Expose it via STAT_FIELD_SUB(subsys, arm_effective_<arm>) in
 *      stats/subsys/<childop>.c so it appears in --stats-json output.
 *   3. Call CHILDOP_ARM_EFFECTIVE(subsys, arm) at the point of first
 *      detectable output within the arm body.
 *   4. Add a paired RAN_NO_EFFECT check in dump_stats_dead_arm_check()
 *      alongside the existing DEAD_ARM check for that arm.
 *
 * Caller must have shm.h in scope (child.h pulls it in transitively).
 *
 * op:  stats subsystem field name (e.g. afxdp_churn)
 * arm: arm_effective_* suffix    (e.g. bind)
 */
#define CHILDOP_ARM_EFFECTIVE(op, arm) \
	__atomic_add_fetch(&shm->stats.op.arm_effective_##arm, 1, __ATOMIC_RELAXED)
