#ifndef _CHILD_INTERNAL_H
#define _CHILD_INTERNAL_H 1

#include "child-api.h"

/*
 * Internal-only declarations for symbols shared between the
 * compilation units that make up the child fuzz loop: child.c (the
 * main loop) and the child-*.c files it calls across the TU boundary.
 * Each group below names the file that defines it.
 *
 * They are deliberately NOT part of the public include/child.h:
 * callers outside the child loop should keep going through the public
 * APIs (init_child, child_process, etc.); these declarations widen
 * linkage only as far as the loop's own files need.
 */

/* child-init-core.c -- init_child() is the lone setup entry point
 * the child_process() loop calls; its body is the readable phase
 * map that sequences the sibling child-init-* phase files. */
void init_child(struct childdata *child, int childno);

/* child-init-clean.c -- the per-iter sibling-childdata refreeze in
 * child.c calls freeze_sibling_childdata across the TU boundary;
 * the coredump toggles bracket the child_process() debug loop; the
 * tainted-mask read fires on the soft-taint watcher path.  The
 * fault-injector helpers (set_make_it_fail / open_fail_nth /
 * open_tainted_fd) and the FPU dirtier are called by
 * init_child_setup_sandbox in child-init-sandbox.c across the TU
 * boundary. */
void freeze_sibling_childdata(int my_childno);
void disable_coredumps(void);
unsigned long read_tainted_mask(int fd);
void set_make_it_fail(void);
void open_fail_nth(struct childdata *child);
void open_tainted_fd(struct childdata *child);
void use_fpu(void);

/* child-init-isolate.c -- stdio + controlling-terminal isolation
 * that init_child (in child-init-core.c) runs as the first phase. */
void init_child_isolate_io(void);

/* child-init-freeze.c -- the initial sibling-childdata freeze + one-
 * shot shared-region pins, and the parent rendezvous / per-child
 * PRNG + object-pool bring-up that follows.  init_child (in
 * child-init-core.c) calls both across the TU boundary. */
void init_child_freeze_shared(struct childdata *child, int childno);
void init_child_rendezvous_parent(struct childdata *child, int childno);

/* child-init-sandbox.c -- shm->ready barrier, fault-injector arm,
 * signal mask, per-child unshare()s, root-only drop_privs,
 * capset()-to-empty + oracle anchor capture, and the random rlimit
 * / umask sweep in munge_process.  init_child (in child-init-core.c)
 * calls this across the TU boundary.
 * child_userns_lane_is_active() returns true iff this child entered
 * the userns-admin lane (used by the cap-drop oracle to select the
 * correct SO_RCVBUFFORCE probe direction). */
void init_child_setup_sandbox(struct childdata *child, int childno);
bool child_userns_lane_is_active(void);

/* child-pidns-init.c -- the idle init that holds pid 1 of a pid
 * namespace the child unshared, started by init_child_setup_sandbox
 * across the TU boundary, which then records where the child's forks
 * land; the child_process() loop polls pidns_init_lost() and recycles
 * the child once the init is gone. */
pid_t start_pidns_init(void);
bool pidns_init_lost(void);
void pidns_note_fork_target(void);

/* child-init-runtime.c -- kcov bring-up, uniarch active-syscalls
 * pin, explorer-pool slot flag, the A/B-comparison cohort stamps,
 * heap-bounds re-snapshot, RLIMIT_AS pin, and one-shot
 * disable_coredumps.  init_child (in child-init-core.c) calls this
 * across the TU boundary as the last phase. */
void init_child_runtime_config(struct childdata *child, int childno);

/* child-altop-* quartet -- used by child.c::child_process for the
 * per-iter op-type pick (child-altop-pick.c), the per-call
 * adapt_budget feedback (child-altop-budget.c), and the indexed
 * dispatch into op_dispatch[] (child-altop-table.c). */
enum child_op_type pick_op_type(void);
void adapt_budget(enum child_op_type op_type, unsigned long edges_this_call);
extern bool (*const op_dispatch[NR_CHILD_OP_TYPES])(struct childdata *);

/* child-periodic.c -- the every-16-ops periodic_work() maintenance
 * tick invoked from the child_process() main loop.  Its parent-pid
 * watchdog helper stays static in that TU (single caller). */
void periodic_work(struct childdata *child, unsigned long op_nr);

/* child-watchdog.c -- stall detection consulted from child_process()
 * every time SIGALRM is observed.  The per-op-type threshold table
 * (stall_threshold) stays static in that TU (single caller). */
bool check_stall(struct childdata *child);

/* child-dispatch-arm.c -- helpers the alt-op dispatch arm in
 * child_process() consults each iteration: the lowest-free-fd probe
 * that brackets each alt-op dispatch to detect fd leaks, and the
 * per-child corruption-rate storm-recycle check gated on the
 * LOCAL_STORM_CHECK_PERIOD cadence. */
int probe_lowest_free_fd(bool *at_ceiling);
bool storm_rate_recycle(struct childdata *child);

#endif /* _CHILD_INTERNAL_H */
