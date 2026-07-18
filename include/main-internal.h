#pragma once

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
 * and reused across epochs (cleared in reset_epoch_state()).  Live in
 * parent address space, not in shm, so child stray writes cannot
 * scribble them. */
extern int *pidstatfiles;
extern pid_t *zombie_pids;
extern time_t *zombie_since;
extern time_t *spawn_times;

/* Updated by check_children_progressing(), read by print_stats. */
extern unsigned long hiscore;
extern unsigned int stall_count;

/* main/reap.c -- exposed entry points. */
int shm_is_corrupt(void);
int open_child_pidstat(pid_t target);
char get_pid_state(int childno);
int find_free_childno(void);
void handle_children(void);
void check_children_progressing(void);
void kill_all_kids(void);
void reap_dead_kids(void);
void process_zombie_pending(void);
void dstate_diag_get_counts(unsigned int *printed, unsigned int *omitted,
			    unsigned int *sigs);

/* main/spawn.c -- exposed entry points. */
void replace_child(int childno);
void fork_children(void);
void dump_proc_self_status(void);
void final_state_save(void);

/* main/stats.c -- exposed entry points. */
void print_stats(void);
