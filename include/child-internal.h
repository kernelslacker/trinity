#ifndef _CHILD_INTERNAL_H
#define _CHILD_INTERNAL_H 1

#include "child.h"

/*
 * Internal-only declarations for symbols shared between the three
 * compilation units that make up the child fuzz loop: child.c (the
 * main loop), child-init.c (per-child setup), and child-altop.c (the
 * alt-op picker / dispatch / scoring machinery).
 *
 * Symbols here were file-static before the TU split.  They are
 * deliberately NOT promoted into the public include/child.h: callers
 * outside the child trio should keep going through the public APIs
 * (init_child, child_process, etc.); these declarations widen
 * linkage only as far as the split demands.
 */

/* child-init.c -- init_child() is the lone setup entry point the
 * child_process() loop calls; the rest of these crossed the boundary
 * for the per-iter sibling-childdata refreeze, the coredump toggle
 * around shm->debug, and the taint mask read on the soft-taint
 * watcher path. */
void init_child(struct childdata *child, int childno);
void freeze_sibling_childdata(int my_childno);
void disable_coredumps(void);
void enable_coredumps(void);
unsigned long read_tainted_mask(int fd);

/* child-altop.c -- used by child.c::child_process for the per-iter
 * op-type pick, the per-call adapt_budget feedback, and the
 * indexed dispatch into op_dispatch[]. */
enum child_op_type pick_op_type(void);
void adapt_budget(enum child_op_type op_type, unsigned long edges_this_call);
extern bool (*const op_dispatch[NR_CHILD_OP_TYPES])(struct childdata *);

#endif /* _CHILD_INTERNAL_H */
