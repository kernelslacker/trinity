/*
 * Self-check for expensive_accept() (random_syscall/pick-common.c), the
 * adaptive accept rate of EXPENSIVE syscalls.  A biarch build's two
 * tables give one number to different syscalls, so the rate earned by
 * one must come from its own ABI's counters and warm-start priors, not
 * its twin's.  SHADOW_ONLY counts a sub-floor rate without drawing on
 * it, which the checks read.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "debug.h"		/* BUG */
#include "kcov.h"
#include "picker-context.h"	/* PICKER_CTX_INIT */
#include "random-syscall-internal.h"	/* expensive_accept */
#include "shm.h"
#include "tables.h"		/* syscall_is_expensive */

#define NR	3

/* tables/table-copy.c is not linked: NR is the one EXPENSIVE syscall,
 * in both tables. */
bool syscall_is_expensive(unsigned int nr, bool do32)
{
	(void) do32;
	return nr == NR;
}

static void set_counts(bool do32, unsigned long calls, unsigned long edges)
{
	kcov_shm->per_syscall.per_syscall_calls[NR][PICKER_CTX_INIT][do32] = calls;
	kcov_shm->per_syscall.per_syscall_edges[NR][PICKER_CTX_INIT][do32] = edges;
}

static void set_priors(bool do32, unsigned long calls, unsigned long edges)
{
	kcov_shm->per_syscall.per_syscall_calls_prior[NR][do32] = calls;
	kcov_shm->per_syscall.per_syscall_edges_prior[NR][do32] = edges;
}

/* Did one look at NR under @do32 earn a rate under the floor? */
static bool sub_floor(bool do32)
{
	unsigned long before = shm->stats.expensive_adaptive.extra_accepts;

	(void) expensive_accept(NR, do32);
	return shm->stats.expensive_adaptive.extra_accepts != before;
}

/* Did one look at NR under @do32 pull a sub-floor rate back toward
 * the floor? */
static bool demoted(bool do32)
{
	unsigned long before = shm->stats.expensive_adaptive.demotes;

	(void) expensive_accept(NR, do32);
	return shm->stats.expensive_adaptive.demotes != before;
}

/* @live_abi has produced an edge on every other call, the last of them
 * just now; its twin has been called as often for nothing. */
static void check_twins(bool live_abi, const char *what)
{
	bool live = sub_floor(live_abi);
	bool dead = sub_floor(!live_abi);

	if (!live || dead) {
		fprintf(stderr, "\n    expensive accept: dead %s twin: live slot %s, dead slot %s the floor",
			what, live ? "under" : "at", dead ? "under" : "at");
		BUG("expensive accept: one ABI's counters set its twin's rate");
	}
}

void expensive_accept_self_check(void);
void expensive_accept_self_check(void)
{
	enum expensive_adaptive_mode saved = expensive_adaptive_mode;

	expensive_adaptive_mode = EXPENSIVE_ADAPTIVE_MODE_SHADOW_ONLY;
	kcov_shm = calloc(1, sizeof(*kcov_shm));
	if (kcov_shm == NULL)
		BUG("expensive accept: calloc failed");
	kcov_shm->coverage.total_calls = 4000;
	kcov_shm->per_syscall.last_edge_at[NR][0] = 4000;
	kcov_shm->per_syscall.last_edge_at[NR][1] = 4000;

	set_counts(false, 1000, 500);
	set_counts(true, 1000, 0);
	check_twins(false, "compat");

	set_counts(false, 1000, 0);
	set_counts(true, 1000, 500);
	check_twins(true, "native");

	/* The same from last run's evidence alone. */
	set_counts(false, 0, 0);
	set_counts(true, 0, 0);
	set_priors(false, 1000, 500);
	set_priors(true, 1000, 0);
	check_twins(false, "compat prior");

	/* Both twins productive, the native one with an edge just now, the
	 * compat one with none for more than two cold thresholds: the
	 * stale decay pulls back the compat rate alone. */
	set_priors(false, 0, 0);
	set_priors(true, 0, 0);
	set_counts(false, 1000, 500);
	set_counts(true, 1000, 500);
	kcov_shm->coverage.total_calls = 3 * KCOV_COLD_THRESHOLD;
	kcov_shm->per_syscall.last_edge_at[NR][0] = 3 * KCOV_COLD_THRESHOLD;
	kcov_shm->per_syscall.last_edge_at[NR][1] = KCOV_COLD_THRESHOLD - 1;
	if (demoted(false) || !demoted(true))
		BUG("expensive accept: one ABI's last edge set its twin's decay");

	free(kcov_shm);
	kcov_shm = NULL;
	expensive_adaptive_mode = saved;
}
