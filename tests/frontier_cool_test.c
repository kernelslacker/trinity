/*
 * Self-check for the SHADOW cooldown discriminators in
 * strategy/strategy-frontier-cool.c.  A biarch build's two tables give
 * one number to different syscalls, so the call floors that admit a
 * syscall as a cooldown candidate must count its own ABI's calls, not
 * its twin's as well.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "debug.h"		/* BUG */
#include "kcov.h"
#include "picker-context.h"	/* PICKER_CTX_INIT */
#include "shm.h"
#include "strategy.h"

#define NR	3

/* strategy/strategy.c and the rest of the frontier cluster are not
 * linked: both discriminators in SHADOW, no spare lane fires, and the
 * frontier ring is empty. */
enum frontier_saturation_cooldown_mode frontier_saturation_cooldown_mode =
	FRONTIER_SATURATION_COOLDOWN_MODE_SHADOW_ONLY;
enum frontier_live_cooldown_mode frontier_live_cooldown_mode =
	FRONTIER_LIVE_COOLDOWN_MODE_SHADOW_ONLY;
enum frontier_barren_demote_mode frontier_barren_demote_mode =
	FRONTIER_BARREN_DEMOTE_MODE_OFF;

enum frontier_spare_reason frontier_spare_lane_decide(unsigned int syscallnr,
						      bool do32)
{
	(void) syscallnr;
	(void) do32;
	return FRONTIER_SPARE_NONE;
}

unsigned long frontier_recent_count(unsigned int nr)
{
	(void) nr;
	return 0;
}

static void set_calls(bool do32, unsigned long calls)
{
	kcov_shm->per_syscall.per_syscall_calls[NR][PICKER_CTX_INIT][do32] = calls;
}

/* Each ABI's syscall was called once short of @floor, so neither is a
 * candidate, though the two together pass it. */
static void check_floor(void (*spare)(unsigned int, bool),
			const unsigned long *candidates, unsigned long floor,
			const char *what)
{
	unsigned long before = *candidates;

	set_calls(false, floor - 1);
	set_calls(true, floor - 1);
	spare(NR, false);
	spare(NR, true);
	if (*candidates != before) {
		fprintf(stderr, "\n    frontier cool: %s: %lu candidates under the %lu-call floor",
			what, *candidates - before, floor);
		BUG("frontier cool: a twin's calls lifted a syscall over its floor");
	}

	/* One more call of its own puts the native syscall over. */
	set_calls(false, floor);
	spare(NR, false);
	spare(NR, true);
	if (*candidates != before + 1) {
		fprintf(stderr, "\n    frontier cool: %s: %lu candidates, want 1",
			what, *candidates - before);
		BUG("frontier cool: the floor did not admit the syscall that passed it");
	}
}

void frontier_cool_self_check(void);
void frontier_cool_self_check(void)
{
	kcov_shm = calloc(1, sizeof(*kcov_shm));
	if (kcov_shm == NULL)
		BUG("frontier cool: calloc failed");

	check_floor(frontier_satcool_spare,
		    &shm->stats.frontier.saturation.satcool_candidates,
		    FRONTIER_SATCOOL_CMIN, "saturation cooldown");
	check_floor(frontier_live_cool_spare,
		    &shm->stats.frontier.discriminator.live_cool_candidates,
		    FRONTIER_LIVE_COOL_CMIN, "live cooldown");

	free(kcov_shm);
	kcov_shm = NULL;
}
