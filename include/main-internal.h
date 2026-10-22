#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "child-api.h"

/*
 * Cross-translation-unit interface for the main/loop.c split: parent-only
 * symbols shared between main/loop.c (epoch driver), main/reap.c (reap +
 * watchdog), main/spawn.c (spawn/fork + fork-failure forensic), and
 * main/stats.c (per-tick stats printing).  Not part of the public
 * trinity API -- callers outside the main.* family must keep going
 * through trinity.h / child.h / etc.
 */

/* Parent-private per-childno arrays.  Allocated once in main_loop()
 * and reused across epochs.  reset_epoch_state() clears pidstatfiles[]
 * and spawn_times[] but never writes the zombie_* arrays, so a
 * zombie-pending or quarantined slot stays parked into the next epoch;
 * process_zombie_pending() empties zombie_pids[]/zombie_since[] when it
 * retires or quarantines a slot.  Live in parent address space, not in
 * shm, so child stray writes cannot scribble them. */
extern int *pidstatfiles;
extern pid_t *zombie_pids;
extern time_t *zombie_since;
extern bool *zombie_quarantined;
extern time_t *spawn_times;
/* Number of non-quarantined slots available for forking. */
extern unsigned int live_child_slots;
/* Count quarantined slots in [lo, hi) — for live_child_slots and the
 * per-lane pool sizes. */
unsigned int count_quarantined_in_range(unsigned int lo, unsigned int hi);

/* Updated by check_children_progressing(), read by print_stats. */
extern unsigned long hiscore;
extern unsigned int stall_count;

/* main/loop.c -- exposed entry points. */
/* Reset a taskless slot's rings from the parent-private canaries and point
 * its childdata back at them; call after clean_childdata(). */
void reset_child_rings(unsigned int childno);
/* The shutdown tail: kill and reap children until the pid map is empty,
 * parking any the kernel will not release. */
void wait_for_children_to_exit(void);

/* main/reap.c -- exposed entry points. */
int shm_is_corrupt(void);
int open_child_pidstat(pid_t target);
char get_pid_state(int childno);
int find_free_childno(const bool *skip);
unsigned int handle_children(void);
void check_children_progressing(void);
void kill_all_kids(void);
void reap_dead_kids(void);
void process_zombie_pending(void);
/* main/reap-zombie.c -- park a slot whose task the kernel has not released. */
void register_zombie_slot(int childno, pid_t pid, const char *reason);
void dstate_diag_get_counts(unsigned int *printed, unsigned int *omitted,
			    unsigned int *sigs);

/* main/spawn.c -- exposed entry points. */
/* CLOCK_MONOTONIC ns at which a startup fill whose spawns keep failing
 * opens the barrier anyway; reset_epoch_state() clears it. */
extern uint64_t spawn_stall_deadline;
void replace_child(int childno);
void fork_children(void);
void dump_proc_self_status(void);
void final_state_save(void);

/* main/stats.c -- exposed entry points. */
void print_stats(void);
