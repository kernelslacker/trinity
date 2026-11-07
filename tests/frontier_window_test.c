/*
 * Self-check for frontier_window_advance(): each rotation keeps a syscall's
 * cached frontier weight equal to what its ring holds, so the picker's
 * weight and the ring it summarises cannot drift apart.  The live-miss
 * cooldown halves both, and an edge recorded after it is aged out only
 * when its own slot retires.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"		/* biarch */
#include "debug.h"		/* BUG */
#include "picker-context.h"
#include "shm.h"
#include "strategy.h"
#include "tables.h"		/* max_nr_syscalls */

#define NR	0U

static uint32_t ring_sum(void)
{
	uint32_t sum = 0;
	unsigned int s;

	for (s = 0; s < FRONTIER_DECAY_WINDOWS; s++)
		sum += shm->frontier_history[NR][PICKER_CTX_INIT][s];
	return sum;
}

/* A producer's new edge, as frontier_record_new_edge() records it. */
static void record_edge(void)
{
	uint32_t slot = shm->frontier_slot & (FRONTIER_DECAY_WINDOWS - 1);

	shm->frontier_history[NR][PICKER_CTX_INIT][slot]++;
	shm->frontier_recent_count_cached[NR][PICKER_CTX_INIT]++;
}

static void rotate_in_sync(const char *what)
{
	unsigned long clamped = shm->stats.frontier.core.underflow_prevented;

	frontier_window_advance();
	if (shm->frontier_recent_count_cached[NR][PICKER_CTX_INIT] != ring_sum())
		BUG(what);
	if (shm->stats.frontier.core.underflow_prevented != clamped)
		BUG("frontier window: a rotation took more off the weight than it held");
}

void frontier_window_self_check(void);
void frontier_window_self_check(void)
{
	unsigned int s, i;

	biarch = false;
	max_nr_syscalls = NR + 1;
	memset(shm->frontier_history[NR], 0, sizeof(shm->frontier_history[NR]));
	for (s = 0; s < FRONTIER_DECAY_WINDOWS; s++)
		shm->frontier_history[NR][PICKER_CTX_INIT][s] = 4;
	shm->frontier_recent_count_cached[NR][PICKER_CTX_INIT] = ring_sum();
	shm->frontier_slot = FRONTIER_DECAY_WINDOWS - 1;

	shm->stats.frontier.per_syscall.live_miss_streak_per_syscall[NR] =
		FRONTIER_LIVE_MISS_COOLDOWN;
	rotate_in_sync("frontier window: the cooldown halved the weight but not the ring");
	if (ring_sum() != 7 * 2)
		BUG("frontier window: the cooldown did not halve the live slots");

	shm->stats.frontier.per_syscall.live_miss_streak_per_syscall[NR] = 0;
	rotate_in_sync("frontier window: a rotation after the cooldown left the weight off the ring");
	record_edge();
	for (i = 0; i < FRONTIER_DECAY_WINDOWS - 1; i++)
		rotate_in_sync("frontier window: an edge after the cooldown left the weight off the ring");
	if (ring_sum() != 1)
		BUG("frontier window: an edge recorded after the cooldown aged out before its slot");
	rotate_in_sync("frontier window: the edge's own slot did not take it off the weight");
	if (ring_sum() != 0)
		BUG("frontier window: an edge outlived its slot");

	memset(shm->frontier_history[NR], 0, sizeof(shm->frontier_history[NR]));
	memset(shm->frontier_recent_count_cached[NR], 0,
	       sizeof(shm->frontier_recent_count_cached[NR]));
	shm->frontier_slot = 0;
	shm->frontier_max_weight_cached = 0;
	max_nr_syscalls = 0;
}
