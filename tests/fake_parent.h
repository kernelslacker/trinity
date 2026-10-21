/*
 * Fake parent fleet for the tests that link main/loop.c and
 * main/reap-zombie.c (PARENT_SRCS in tests/Makefile).  fake_parent.c
 * backs the parent globals those files read with FAKE_NR_CHILDREN
 * static slots, and logs the per-slot parent calls they make.
 */
#pragma once

#include <sys/types.h>

#define FAKE_NR_CHILDREN	16

struct fake_slot_log {
	unsigned int cleaned;		/* clean_childdata() */
	unsigned int ring_reset;	/* fd_event_ring_init() */
	pid_t classified_pid;		/* classify_child_buglog() */
	unsigned int sysv_drained;	/* reap_child_sysv_{shm,msg,sem}() */
	unsigned int replaced;		/* replace_child() */
};

extern struct fake_slot_log fake_slot_log[FAKE_NR_CHILDREN];

/* Start a run: every slot empty and in service, the zombie reaper's
 * state and counters cleared, the log zeroed. */
void fake_parent_reset(void);
