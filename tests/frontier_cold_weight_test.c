/*
 * Self-check for frontier_cold_weight() (random_syscall/
 * pick-frontier-weight.c), the coverage-frontier picker's weight for a
 * syscall once the frontier ring goes silent.  A biarch build's two
 * tables give one number to different syscalls, so the weight of one
 * must come from its own ABI's call, edge and per-call yield counters,
 * not its twin's.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "child.h"
#include "debug.h"		/* BUG */
#include "kcov.h"
#include "picker-context.h"	/* PICKER_CTX_INIT */
#include "random-syscall-internal.h"

#define NR	3

/* kcov/kcov.c is not linked: the transition term stays out of the
 * blend, as under the default mode. */
enum kcov_transition_reward_mode kcov_transition_reward_mode =
	KCOV_TRANSITION_REWARD_OFF;

static void set_counts(bool do32, unsigned long calls, unsigned long edges)
{
	kcov_shm->per_syscall.per_syscall_calls[NR][PICKER_CTX_INIT][do32] = calls;
	kcov_shm->per_syscall.per_syscall_edges[NR][PICKER_CTX_INIT][do32] = edges;
}

static void check_weight(bool do32, struct childdata *child,
			 unsigned long want, const char *what)
{
	unsigned long got = frontier_cold_weight(NR, do32, child);

	if (got != want) {
		fprintf(stderr, "\n    frontier cold weight: %s: %lu, want %lu",
			what, got, want);
		BUG("frontier cold weight: one ABI's counters weighed its twin");
	}
}

void frontier_cold_weight_self_check(void);
void frontier_cold_weight_self_check(void)
{
	struct childdata *blend_child;

	kcov_shm = calloc(1, sizeof(*kcov_shm));
	blend_child = calloc(1, sizeof(*blend_child));
	if (kcov_shm == NULL || blend_child == NULL)
		BUG("frontier cold weight: calloc failed");

	/* One call in four of the native syscall found an edge; its twin,
	 * called as often, never did, which leaves it no weight. */
	set_counts(false, 1000, 250);
	set_counts(true, 1000, 0);
	check_weight(false, NULL, FRONTIER_COLD_SCALE * 3 / 4,
		     "native syscall beside a dead twin");
	check_weight(true, NULL, 0, "dead compat syscall beside a live twin");

	/* The blend adds credit for each call's bucket transitions and
	 * first-seen PCs; a twin's yield must not lower the weight. */
	blend_child->frontier_blend_arm_b = true;
	kcov_shm->per_syscall_cmp.per_syscall_diag[NR][1].bucket_bits_real = 1UL << 20;
	kcov_shm->per_syscall_cmp.per_syscall_diag[NR][1].distinct_pcs = 1UL << 20;
	check_weight(false, blend_child, FRONTIER_COLD_SCALE * 3 / 4,
		     "blend of a native syscall beside a yielding twin");

	free(blend_child);
	free(kcov_shm);
	kcov_shm = NULL;
}
