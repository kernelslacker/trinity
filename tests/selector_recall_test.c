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
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "sanitise.h"		/* get_writable_address */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_clock_getres, ... */
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

/* An oracle that takes its selector in a1 and the buffer the kernel
 * answers into in a2, and the counter it bumps. */
struct selector_oracle {
	struct syscallentry *entry;
	unsigned long *anomalies;
};

/* @o's calls the sanitiser drew on selector @built, which the kernel ran
 * on @ran, each answering the @len bytes at @answer; the anomalies the
 * re-call reports. */
static unsigned long selector_anomalies(const struct selector_oracle *o,
					unsigned long built, unsigned long ran,
					const void *answer, size_t len)
{
	unsigned long before = *o->anomalies;
	unsigned int i, tries;

	for (i = 0; i < RECALL_CALLS; i++) {
		for (tries = 0; tries < DRAW_TRIES; tries++) {
			memset(&rec, 0, sizeof(rec));
			rec.a1 = built;
			rec.a2 = (unsigned long) get_writable_address(len);
			o->entry->sanitise(&rec);
			if (rec.a1 == built)
				break;
			free((void *) rec.post_state);
		}
		if (tries == DRAW_TRIES)
			BUG("a sanitiser never drew the selector");

		memcpy((void *) rec.a2, answer, len);
		rec.a1 = ran;
		shadow_slots(o->entry);
		rec.retval = 0;
		o->entry->post(&rec);
	}
	return *o->anomalies - before;
}

/* A high-resolution clock and a coarse one, whose resolutions differ. */
static void clock_getres_cases(void)
{
	const struct selector_oracle o = {
		&syscall_clock_getres, &shm->stats.oracle.clock_getres_oracle_anomalies,
	};
	struct timespec fine, coarse;

	if (clock_getres(CLOCK_MONOTONIC, &fine) != 0 ||
	    clock_getres(CLOCK_MONOTONIC_COARSE, &coarse) != 0)
		BUG("selector recall: no clock resolutions to compare");
	if (fine.tv_sec == coarse.tv_sec && fine.tv_nsec == coarse.tv_nsec) {
		printf("(clock resolutions alike) ");
		return;
	}

	check("clock_getres: a call rewritten onto another clock was re-called on the first",
	      selector_anomalies(&o, CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC,
				 &fine, sizeof(fine)) == 0);
	check("clock_getres: a rewritten call answering the first clock's resolution was not reported",
	      selector_anomalies(&o, CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE,
				 &fine, sizeof(fine)) > 0);
}

#if defined(SYS_getrlimit) || defined(__NR_getrlimit)
/* Two resources whose limits differ. */
static void getrlimit_cases(void)
{
	const struct selector_oracle o = {
		&syscall_getrlimit, &shm->stats.oracle.getrlimit_oracle_anomalies,
	};
	struct rlimit files, stack;

	if (getrlimit(RLIMIT_NOFILE, &files) != 0 ||
	    getrlimit(RLIMIT_STACK, &stack) != 0)
		BUG("selector recall: no resource limits to compare");
	if (files.rlim_cur == stack.rlim_cur && files.rlim_max == stack.rlim_max) {
		printf("(resource limits alike) ");
		return;
	}

	check("getrlimit: a call rewritten onto another resource was re-called on the first",
	      selector_anomalies(&o, RLIMIT_STACK, RLIMIT_NOFILE,
				 &files, sizeof(files)) == 0);
	check("getrlimit: a rewritten call answering the first resource's limits was not reported",
	      selector_anomalies(&o, RLIMIT_NOFILE, RLIMIT_STACK,
				 &files, sizeof(files)) > 0);
}
#endif

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
#if defined(SYS_getrlimit) || defined(__NR_getrlimit)
	getrlimit_cases();
#endif

	if (failed != 0)
		BUG("a selector re-call asked about the wrong selector");
}
