#pragma once

/*
 * Private cross-file declarations shared between the main/reap-*.c
 * translation units.  Not part of the public trinity API -- callers
 * outside the main/reap-*.c family go through include/main-internal.h.
 */

#include <sys/types.h>

#include "child-api.h"

/* main/reap.c -- reap-core helpers reused by watchdog / signal paths. */
void reap_child(struct childdata *child, int childno, bool child_dead);

/* main/reap-fastdie.c -- fork-die-respawn busy-loop detector. */
void record_reap(int childno, int childstatus);

/* main/reap-dstate.c -- bounded /proc readers + D-state diag budget. */
void dump_pid_stack(int pid);
void dump_pid_syscall(int pid);
ssize_t read_pid_wchan(int pid, char *buf, size_t bufsz);
void dump_dstate_diagnostics(struct childdata *child, int childno, pid_t pid);
bool dstate_diag_budget_take(struct childdata *child, const char *wchan);

/* main/reap-zombie.c -- deferred D-state slot lifecycle. */
void register_zombie_slot(int childno, pid_t pid);
