/*
 * Fake parent fleet for the tests that link main/loop.c, main/reap.c
 * and main/reap-zombie.c (PARENT_SRCS in tests/Makefile).
 * fake_parent.c backs the parent globals those files read with
 * FAKE_NR_CHILDREN static slots, and logs the parent calls they make.
 */
#pragma once

#include <sys/types.h>

#define FAKE_NR_CHILDREN	16

struct fake_slot_log {
	unsigned int cleaned;		/* clean_childdata() */
	unsigned int ring_reset;	/* fd_event_ring_init() */
	unsigned int stats_ring_reset;	/* stats_ring_init() */
	pid_t classified_pid;		/* classify_child_buglog() */
	unsigned int sysv_drained;	/* reap_child_sysv_{shm,msg,sem}() */
	unsigned int replaced;		/* replace_child() */
};

extern struct fake_slot_log fake_slot_log[FAKE_NR_CHILDREN];

/* fd_event_ring_init() / stats_ring_init() calls handed a pointer that
 * is not one of the slots' rings: a write through a stray pointer. */
extern unsigned int fake_stray_ring_init;

/* The pid kill_pid() was last asked to SIGKILL.  It sends nothing, so
 * the task stays up until the test ends it. */
extern pid_t fake_killed_pid;

/* Everything output() was asked to print since the last reset. */
extern char fake_output_log[];

/* Start a run: every slot empty and in service, the zombie reaper's
 * state and counters cleared, the logs zeroed. */
void fake_parent_reset(void);

/* Fork a task that stays alive until killed and dies with the test,
 * standing in for a child the kernel has not released.  A non-zero
 * @stopsig makes it stop itself with that signal first, unblocked and
 * at its default action, from a process group of its own, so SIGTSTP,
 * SIGTTIN and SIGTTOU stop it too. */
pid_t fake_hold_task(int stopsig);
