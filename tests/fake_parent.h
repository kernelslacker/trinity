/*
 * Fake parent fleet for the tests that link main/loop.c, main/reap.c,
 * main/reap-zombie.c and main/spawn.c (PARENT_SRCS in tests/Makefile).
 * fake_parent.c backs the parent globals those files read with
 * FAKE_NR_CHILDREN static slots, and logs the parent calls they make.
 */
#pragma once

#include <limits.h>
#include <stdint.h>
#include <sys/types.h>

#define FAKE_NR_CHILDREN	16

struct fake_slot_log {
	unsigned int cleaned;		/* clean_childdata() */
	unsigned int ring_reset;	/* fd_event_ring_init() */
	unsigned int stats_ring_reset;	/* stats_ring_init() */
	pid_t classified_pid;		/* classify_child_buglog() */
	unsigned int sysv_drained;	/* reap_child_sysv_{shm,msg,sem}() */
	unsigned int replaced;		/* replace_child() */
	unsigned int canary_crashes;	/* canary_queue_on_crash() */
	int canary_signo;		/* the signo of the last such call */
	unsigned int reaps;		/* record_reap() */
	int reap_status;		/* the wait status of the last such call */
	unsigned int spawns;		/* spawn_child() preparing the slot */
	unsigned int forks;		/* self_cgroup_fork_into_workload() */
};

extern struct fake_slot_log fake_slot_log[FAKE_NR_CHILDREN];

/* fd_event_ring_init() / stats_ring_init() calls handed a pointer that
 * is not one of the slots' rings: a write through a stray pointer. */
extern unsigned int fake_stray_ring_init;

/*
 * The fork spawn_child() makes, for the slot it is preparing: it fails
 * with EAGAIN while fake_fork_fail[slot] is non-zero, counting it down
 * unless it is FAKE_FORK_FAIL_ALWAYS, and otherwise succeeds with
 * FAKE_FORK_PID(slot).  Nothing is forked, and no such pid exists.
 */
#define FAKE_FORK_FAIL_ALWAYS	UINT_MAX
#define FAKE_FORK_PID(slot)	((pid_t)(0x7fff0000 + (slot)))
extern unsigned int fake_fork_fail[FAKE_NR_CHILDREN];

/* While non-zero, get_num_fds() fails with this errno instead of
 * counting.  fake_parent_reset() clears it. */
extern int fake_num_fds_errno;

/* The pid kill_pid() was last asked to SIGKILL.  It sends nothing, so
 * the task stays up until the test ends it. */
extern pid_t fake_killed_pid;

/* Everything output() was asked to print since the last reset. */
extern char fake_output_log[];

/* Start a run: every slot empty and in service, the startup barrier
 * shut, the zombie reaper's and the spawn path's state and counters
 * cleared, every fork succeeding and the fd count real, the logs zeroed,
 * the fake clock stopped. */
void fake_parent_reset(void);

/*
 * A fake CLOCK_MONOTONIC.  Once started, clock_gettime(CLOCK_MONOTONIC)
 * reads it and sleep() and usleep() advance it by the time asked for
 * instead of blocking, so a test can run out a 30 s bound at once.  Code
 * that sleeps past FAKE_CLOCK_LIMIT_S is spinning, and aborts.
 */
#define FAKE_CLOCK_LIMIT_S	3600

void fake_clock_start(void);

/* Fake time since fake_clock_start(). */
uint64_t fake_clock_elapsed_ns(void);

/* sleep() and usleep() calls since fake_clock_start(). */
extern unsigned int fake_sleeps;

/* Called after each sleep, with the clock already advanced. */
extern void (*fake_sleep_hook)(void);

/* Fork a task that stays alive until killed and dies with the test,
 * standing in for a child the kernel has not released.  A non-zero
 * @stopsig makes it stop itself with that signal first, unblocked and
 * at its default action, from a process group of its own, so SIGTSTP,
 * SIGTTIN and SIGTTOU stop it too. */
pid_t fake_hold_task(int stopsig);
