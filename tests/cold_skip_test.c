/*
 * Self-check for kcov_syscall_cold_skip_pct() (kcov/cold-skip.c).  A
 * biarch build's two tables give one number to different syscalls (3 is
 * close natively and read in the compat table), so the verdict on one
 * must come from its own ABI's counters and warm-start priors: a dead
 * twin must not make a productive syscall cold, nor a productive twin
 * shield a dead one.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "debug.h"		/* BUG */
#include "kcov.h"
#include "picker-context.h"	/* PICKER_CTX_INIT */

#define NR	3

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

/* @live_abi has produced edges, the last of them just now; its twin has
 * been called as often for nothing, past the saturation cap's floor. */
static void check_twins(bool live_abi, const char *what)
{
	unsigned int live, dead;

	live = kcov_syscall_cold_skip_pct(NR, live_abi);
	dead = kcov_syscall_cold_skip_pct(NR, !live_abi);
	if (live != 0 || dead != KCOV_SAT_CAP_SKIP_PCT) {
		fprintf(stderr, "\n    cold skip: dead %s twin: live slot %u%%, dead slot %u%% (want 0 and %u)",
			what, live, dead, KCOV_SAT_CAP_SKIP_PCT);
		BUG("cold skip: one ABI's counters judged its twin");
	}
}

void cold_skip_self_check(void);
void cold_skip_self_check(void)
{
	kcov_shm = calloc(1, sizeof(*kcov_shm));
	if (kcov_shm == NULL)
		BUG("cold skip: calloc failed");
	kcov_shm->coverage.total_calls = 10 * KCOV_SAT_CAP_CALLS;
	kcov_shm->per_syscall.last_edge_at[NR] = 10 * KCOV_SAT_CAP_CALLS;

	set_counts(false, 2 * KCOV_SAT_CAP_CALLS, KCOV_SAT_CAP_CALLS);
	set_counts(true, 2 * KCOV_SAT_CAP_CALLS, 0);
	check_twins(false, "compat");

	set_counts(false, 2 * KCOV_SAT_CAP_CALLS, 0);
	set_counts(true, 2 * KCOV_SAT_CAP_CALLS, KCOV_SAT_CAP_CALLS);
	check_twins(true, "native");

	/* The same from last run's evidence alone: nothing called yet this
	 * run, so only the priors can cap a slot. */
	set_counts(false, 0, 0);
	set_counts(true, 0, 0);
	set_priors(false, 2 * KCOV_SAT_CAP_CALLS, KCOV_SAT_CAP_CALLS);
	set_priors(true, 2 * KCOV_SAT_CAP_CALLS, 0);
	check_twins(false, "compat prior");

	free(kcov_shm);
	kcov_shm = NULL;
}
