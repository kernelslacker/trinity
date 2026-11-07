/*
 * Self-check for the re-call oracles keyed on a selector, a clock or a
 * resource: each runs its sanitiser and post handler as shipped, handed the
 * answer the kernel gave for the selector it was handed, and counts the
 * anomalies its sampled re-call reports.  Chain substitution or a RedQueen
 * pin can change the selector after the sanitiser drew it, and the re-call
 * has to ask about the one the kernel answered.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "sanitise.h"		/* get_writable_address */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_clock_getres */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern bool fake_pid_draws;			/* dup_pool_test.c */

static unsigned int failed;

static void check(const char *what, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "selector recall: %s\n", what);
	failed++;
}

/* Calls per case: the re-call is sampled one in a hundred. */
#define RECALL_CALLS	1500

/* Tries for a sanitiser to draw the selector a case builds on. */
#define DRAW_TRIES	100000

static struct syscallrecord rec;

/* The slots the kernel was handed, as __do_syscall() shadows them. */
static void shadow_slots(const struct syscallentry *entry)
{
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned int k;

	for (k = 0; k < ARRAY_SIZE(slots); k++)
		rec.arg_shadow[k] = *slots[k];
	rec.arg_snapshot_mask = entry->arg_snapshot_mask;
}

/* clock_getres() calls the sanitiser drew on clock @built, which the
 * kernel ran on clock @ran, each answering @answer; the anomalies the
 * re-call reports. */
static unsigned long clock_getres_anomalies(clockid_t built, clockid_t ran,
					    const struct timespec *answer)
{
	unsigned long before = shm->stats.oracle.clock_getres_oracle_anomalies;
	unsigned int i, tries;

	for (i = 0; i < RECALL_CALLS; i++) {
		for (tries = 0; tries < DRAW_TRIES; tries++) {
			memset(&rec, 0, sizeof(rec));
			rec.a2 = (unsigned long) get_writable_address(sizeof(*answer));
			syscall_clock_getres.sanitise(&rec);
			if (rec.a1 == (unsigned long) built)
				break;
			free((void *) rec.post_state);
		}
		if (tries == DRAW_TRIES)
			BUG("clock_getres's sanitiser never drew the clock");

		memcpy((void *) rec.a2, answer, sizeof(*answer));
		rec.a1 = (unsigned long) ran;
		shadow_slots(&syscall_clock_getres);
		rec.retval = 0;
		syscall_clock_getres.post(&rec);
	}
	return shm->stats.oracle.clock_getres_oracle_anomalies - before;
}

/* A high-resolution clock and a coarse one, whose resolutions differ. */
static void clock_getres_cases(void)
{
	struct timespec fine, coarse;

	if (clock_getres(CLOCK_MONOTONIC, &fine) != 0 ||
	    clock_getres(CLOCK_MONOTONIC_COARSE, &coarse) != 0)
		BUG("selector recall: no clock resolutions to compare");
	if (fine.tv_sec == coarse.tv_sec && fine.tv_nsec == coarse.tv_nsec) {
		printf("(clock resolutions alike) ");
		return;
	}

	check("clock_getres: a call rewritten onto another clock was re-called on the first",
	      clock_getres_anomalies(CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC, &fine) == 0);
	check("clock_getres: a rewritten call answering the first clock's resolution was not reported",
	      clock_getres_anomalies(CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE, &fine) > 0);
}

void selector_recall_self_check(void);
void selector_recall_self_check(void)
{
	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(page_size) == NULL)
		writable_pool_init();

	fake_pid_draws = true;
	clock_getres_cases();
	fake_pid_draws = false;

	if (failed != 0)
		BUG("a selector re-call asked about the wrong selector");
}
