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

/* A parked slot is refilled by the zombie reaper through
 * replace_child(), never by this loop.  With every empty slot parked
 * there is nothing to fork: the loop opens the barrier and returns,
 * rather than leave it shut for as long as the slots stay parked. */
static void barrier_opens_when_every_empty_slot_is_parked(void)
{
	unsigned int i;

	fake_parent_reset();
	fill_all_but(2, 3);
	for (i = 2; i < 5; i++)
		zombie_pids[i] = FAKE_FORK_PID(i);

	fork_children();

	if (!BARRIER_OPEN)
		BUG("spawn: the barrier stayed shut with every empty slot parked");
	for (i = 2; i < 5; i++) {
		if (fake_slot_log[i].spawns != 0 || pids[i] != EMPTY_PIDSLOT)
			BUG("spawn: forked into a parked slot");
	}
}

/* A slot that fails ten spawns is passed over for the rest of the call,
 * so one that never forks does not stop the others filling or hold the
 * barrier.  It stays empty, which keeps the fleet under target so the
 * next call comes, and the mask starts clear on every call: that call
 * tries the slot again, ten more times. */
static void failing_slot_is_skipped_for_one_call(void)
{
	fake_parent_reset();
	fake_clock_start();
	fill_all_but(0, 3);
	fake_fork_fail[0] = FAKE_FORK_FAIL_ALWAYS;

	fork_children();

	if (fake_slot_log[0].forks != 10)
		BUG("spawn: a slot was not given up on after exactly ten spawns");
	if (pids[1] != FAKE_FORK_PID(1) || pids[2] != FAKE_FORK_PID(2))
		BUG("spawn: a failing slot kept the others from filling");
	if (pids[0] != EMPTY_PIDSLOT || shm->running_childs != FAKE_NR_CHILDREN - 1)
		BUG("spawn: a skipped slot did not stay empty");
	if (!BARRIER_OPEN)
		BUG("spawn: a skipped slot held the barrier shut");

	fork_children();

	if (fake_slot_log[0].forks != 20)
		BUG("spawn: the skip mask carried over into the next call");

	fake_fork_fail[0] = 0;
	fork_children();

	if (pids[0] != FAKE_FORK_PID(0) || shm->running_childs != FAKE_NR_CHILDREN)
		BUG("spawn: a skipped slot was not filled once it could fork");
}

/* The throttle yields only for a slot the call has not skipped: with
 * the one empty slot left skipped, nothing is fillable, the call goes
 * on to open the barrier and does not hand a shut one back. */
static void throttled_fill_does_not_yield_for_a_skipped_slot(void)
{
	fake_parent_reset();
	fake_clock_start();
	fork_throttle_us = 1000;
	fill_all_but(0, 2);
	fake_fork_fail[0] = FAKE_FORK_FAIL_ALWAYS;

	fork_children();

	if (fake_slot_log[0].forks != 10 || pids[1] != FAKE_FORK_PID(1))
		BUG("spawn: a throttled call did not skip the failing slot and fork the next");
	if (!BARRIER_OPEN)
		BUG("spawn: a throttled call yielded for a slot it had skipped");
}

void spawn_self_check(void);
void spawn_self_check(void)
{
	barrier_opens_once_every_slot_fills();
	throttled_fill_yields_after_each_spawn();
	throttled_fill_carries_on_past_a_parked_slot();
	barrier_opens_when_every_empty_slot_is_parked();
	failing_slot_is_skipped_for_one_call();
	throttled_fill_does_not_yield_for_a_skipped_slot();

	/* Leave no pids or counts for later suites. */
	fake_parent_reset();
}
