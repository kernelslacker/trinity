/*
 * Self-checks for fork_children() and replace_child() (main/spawn.c):
 * the startup barrier the fresh children wait at, and the fill that
 * opens it.  The fork is faked per slot (fake_parent.c), so nothing is
 * forked; the slots hold made-up pids.
 */

#include <sys/types.h>

#include "debug.h"		/* BUG */
#include "main-internal.h"
#include "pids.h"
#include "self_cgroup.h"	/* fork_throttle_us */
#include "shm.h"

#include "fake_parent.h"

#define BARRIER_OPEN	(__atomic_load_n(&shm->ready, __ATOMIC_ACQUIRE))

/* Every slot but the @n from @first already holds a child. */
static void fill_all_but(unsigned int first, unsigned int n)
{
	unsigned int i;

	for_each_child(i) {
		if (i >= first && i < first + n)
			continue;
		pids[i] = FAKE_FORK_PID(i);
		shm->running_childs++;
	}
}

/* Nothing fails and nothing throttles: one call forks every slot, and
 * the barrier opens on leaving the loop, once the last one has. */
static void barrier_opens_once_every_slot_fills(void)
{
	unsigned int i;

	fake_parent_reset();

	fork_children();

	for_each_child(i) {
		if (pids[i] != FAKE_FORK_PID(i) || fake_slot_log[i].forks != 1)
			BUG("spawn: a fill did not fork every slot exactly once");
	}
	if (shm->running_childs != FAKE_NR_CHILDREN)
		BUG("spawn: a full fill left the running count short");
	if (!BARRIER_OPEN)
		BUG("spawn: the startup barrier stayed shut with every slot filled");
}

/* Under memory.high pressure a call forks one slot and returns, so the
 * reaper gets a turn between spawns, and the barrier waits for the call
 * that fills the last slot.  The throttle sleeps before every fork. */
static void throttled_fill_yields_after_each_spawn(void)
{
	unsigned int i;

	fake_parent_reset();
	fake_clock_start();
	fork_throttle_us = 1000;

	for (i = 0; i < FAKE_NR_CHILDREN - 1; i++) {
		fork_children();
		if (shm->running_childs != i + 1)
			BUG("spawn: a throttled call did not fork exactly one slot");
		if (BARRIER_OPEN)
			BUG("spawn: the barrier opened before the last slot filled");
	}
	fork_children();
	if (shm->running_childs != FAKE_NR_CHILDREN || !BARRIER_OPEN)
		BUG("spawn: the call that filled the last slot did not open the barrier");
	if (fake_sleeps != FAKE_NR_CHILDREN ||
	    fake_clock_elapsed_ns() != FAKE_NR_CHILDREN * fork_throttle_us * 1000ULL)
		BUG("spawn: the throttle did not sleep before every fork");
}

/* A parked slot cannot be forked, so once the last free slot has been,
 * a throttled call carries on instead of yielding for the parked one:
 * the barrier must not wait on a slot that only the zombie reaper can
 * hand back. */
static void throttled_fill_carries_on_past_a_parked_slot(void)
{
	fake_parent_reset();
	fake_clock_start();
	fork_throttle_us = 1000;
	fill_all_but(3, 2);
	zombie_pids[4] = FAKE_FORK_PID(4);

	fork_children();

	if (pids[3] != FAKE_FORK_PID(3))
		BUG("spawn: the free slot beside a parked one was not forked");
	if (!BARRIER_OPEN)
		BUG("spawn: a throttled call yielded for a parked slot, with the barrier shut");
}

void spawn_self_check(void);
void spawn_self_check(void)
{
	barrier_opens_once_every_slot_fills();
	throttled_fill_yields_after_each_spawn();
	throttled_fill_carries_on_past_a_parked_slot();

	/* Leave no pids or counts for later suites. */
	fake_parent_reset();
}
