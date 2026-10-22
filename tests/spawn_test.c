/*
 * Self-checks for fork_children() and replace_child() (main/spawn.c):
 * the startup barrier the fresh children wait at, and the fill that
 * opens it.  The fork is faked per slot (fake_parent.c), so nothing is
 * forked; the slots hold made-up pids.
 */

#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "debug.h"		/* BUG */
#include "exit.h"
#include "main-internal.h"
#include "params.h"		/* fork_pressure_drain */
#include "pids.h"
#include "self_cgroup.h"	/* fork_throttle_us */
#include "shm.h"
#include "trinity.h"		/* fork_pressure_drain_active, max_files_rlimit */

#include "fake_parent.h"

#define BARRIER_OPEN	(__atomic_load_n(&shm->ready, __ATOMIC_ACQUIRE))

#define NSEC_PER_SEC	1000000000ULL

void __real_replace_child(int childno);

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

/* The line the call that crosses the drain's threshold prints. */
#define DRAIN_ENGAGED	"fork-pressure drain engaged (100 consecutive spawn failures)"

/* Four empty slots that never fork, so a call fails forty spawns, ten
 * for each slot, and the call ends there.  The failure count is static
 * in main/spawn.c and only a fork_children() spawn that succeeds zeroes
 * it, so one does first, to start every test from none. */
static void four_failing_slots(void)
{
	unsigned int i;

	fake_parent_reset();
	fill_all_but(0, 1);
	fork_children();

	fake_parent_reset();
	fake_clock_start();
	fork_pressure_drain = true;
	fill_all_but(0, 4);
	for (i = 0; i < 4; i++)
		fake_fork_fail[i] = FAKE_FORK_FAIL_ALWAYS;
}

/* The drain is opt-in: without --fork-pressure-drain a failure streak
 * well past the threshold suppresses nothing. */
static void drain_stays_off_unless_asked_for(void)
{
	unsigned int i;

	four_failing_slots();
	fork_pressure_drain = false;

	for (i = 0; i < 3; i++)
		fork_children();

	if (strstr(fake_output_log, DRAIN_ENGAGED) != NULL)
		BUG("spawn: the fork-pressure drain engaged without being asked for");
}

/* A call gives up on a slot after ten failures, so a refill of a few
 * slots fails too few spawns to reach the threshold of 100 within one
 * call.  The count has to carry across calls: forty a call crosses it
 * in the third, and not before. */
static void drain_count_carries_across_calls(void)
{
	four_failing_slots();

	fork_children();
	fork_children();
	if (strstr(fake_output_log, DRAIN_ENGAGED) != NULL)
		BUG("spawn: the fork-pressure drain engaged before 100 failures");

	fork_children();
	if (strstr(fake_output_log, DRAIN_ENGAGED) == NULL ||
	    fork_pressure_drain_active() == 0)
		BUG("spawn: the failure count did not carry across calls to the drain threshold");
}

/* The count is of consecutive failures: a spawn that succeeds starts it
 * over, so eighty failures, a success and thirty more are no streak. */
static void spawn_success_restarts_the_drain_count(void)
{
	four_failing_slots();

	fork_children();
	fork_children();
	fake_fork_fail[0] = 0;
	fork_children();

	if (pids[0] != FAKE_FORK_PID(0))
		BUG("spawn: the slot that could fork was not forked");
	if (strstr(fake_output_log, DRAIN_ENGAGED) != NULL)
		BUG("spawn: a spawn that succeeded did not restart the failure count");
}

/* The line the call that opens a stalled fill's barrier prints. */
#define STALL_OPEN	"the startup fill has not grown for 5 s (0 of 16 slots running)"

/* When the barrier was first seen open, as the fake clock saw it from
 * the sleep after the spawn that opened it. */
static uint64_t opened_at;

static void note_barrier_open(void)
{
	if (opened_at == 0 && BARRIER_OPEN)
		opened_at = fake_clock_elapsed_ns();
}

/* All sixteen slots empty and none able to fork, and the sleeps watched
 * for the barrier.  Each call fails spawns for 2 s of backoff and ends
 * there with the barrier shut, so a call is 2 s of fake time. */
static void stalled_fill(void)
{
	unsigned int i;

	fake_parent_reset();
	fake_clock_start();
	opened_at = 0;
	fake_sleep_hook = note_barrier_open;
	for_each_child(i)
		fake_fork_fail[i] = FAKE_FORK_FAIL_ALWAYS;
}

/* Global fork caps fail every spawn, and twelve or more failing slots
 * outlast the backoff budget, so the fill never skips them all and the
 * skip-everything return never opens the barrier.  The children that
 * did fork would wait at it as long as the cap holds, so the barrier
 * opens once spawns have failed for 5 s straight: not in the first two
 * calls, 4 s of failures, but 5 s in, a second into the third, and
 * logged once. */
static void stalled_fill_opens_the_barrier_at_five_seconds(void)
{
	char *first;

	stalled_fill();

	fork_children();
	fork_children();
	if (BARRIER_OPEN)
		BUG("spawn: the barrier opened before spawns had failed for 5 s");

	fork_children();
	if (!BARRIER_OPEN)
		BUG("spawn: spawns that failed for 5 s did not open the barrier");
	if (opened_at < 5 * NSEC_PER_SEC || opened_at >= 5 * NSEC_PER_SEC + NSEC_PER_SEC / 10)
		BUG("spawn: the barrier did not open 5 s after the first failed spawn");

	fork_children();
	first = strstr(fake_output_log, STALL_OPEN);
	if (first == NULL || strstr(first + 1, STALL_OPEN) != NULL)
		BUG("spawn: the stalled fill did not log its opening of the barrier once");
}

/* The deadline is for failures with no spawn between: one that
 * succeeds restarts the 5 s, so a fill that keeps landing spawns never
 * trips it however slowly it grows.  Here slot 0 forks at 4 s, and the
 * barrier waits for a deadline 5 s after the failure that followed. */
static void spawn_success_restarts_the_stall_deadline(void)
{
	stalled_fill();

	fork_children();
	fork_children();
	fake_fork_fail[0] = 0;
	fork_children();
	fork_children();
	if (BARRIER_OPEN)
		BUG("spawn: a spawn that succeeded did not restart the stall deadline");

	fork_children();
	if (!BARRIER_OPEN)
		BUG("spawn: a fill that failed for 5 s since its last spawn did not open the barrier");
	if (opened_at < 9 * NSEC_PER_SEC || opened_at >= 9 * NSEC_PER_SEC + NSEC_PER_SEC / 10)
		BUG("spawn: the barrier did not open 5 s after the failure that followed the spawn");
}

/* A refill by replace_child() can win a pid the reaper just freed while
 * the fill keeps failing, so it is no evidence of progress: it neither
 * arms the deadline nor clears one. */
static void replace_child_leaves_the_stall_deadline_alone(void)
{
	fake_parent_reset();
	fake_clock_start();
	fake_fork_fail[3] = FAKE_FORK_FAIL_ALWAYS;

	__real_replace_child(3);
	if (spawn_stall_deadline != 0)
		BUG("spawn: a failed refill armed the stall deadline");

	spawn_stall_deadline = 1;
	fake_fork_fail[3] = 0;
	__real_replace_child(3);
	if (pids[3] != FAKE_FORK_PID(3) || spawn_stall_deadline != 1)
		BUG("spawn: a refill that succeeded cleared the stall deadline");
}

/* The two ways a run starts to stop that the spawn path checks for:
 * an exit reason, which a child's BUG or the epoch limits stamp, and
 * the flag the shutdown raises to keep anything new from forking. */
enum stop_kind {
	STOP_EXIT_REASON,
	STOP_SPAWN_NO_MORE,
};

static enum stop_kind stopping_how;

static void stop_the_run(void)
{
	if (stopping_how == STOP_EXIT_REASON)
		__atomic_store_n(&shm->exit_reason, EXIT_USER_REQUEST,
				 __ATOMIC_RELAXED);
	else
		__atomic_store_n(&shm->spawn_no_more, true, __ATOMIC_RELEASE);
}

/* A refill into a run that is already stopping forks a child the
 * shutdown would only have to kill and reap. */
static void refill_forks_nothing_into_a_stopping_run(enum stop_kind how)
{
	fake_parent_reset();
	stopping_how = how;
	stop_the_run();

	__real_replace_child(3);

	if (fake_slot_log[3].spawns != 0)
		BUG("spawn: a refill forked into a run that was stopping");
}

/* A spawn that fails because it stopped the run, as it does close to the
 * fd limit, is no fork failure: the refill gives up on the spot, with
 * no retry and no backoff to sit through. */
static void refill_stops_at_a_spawn_that_stopped_the_run(void)
{
	fake_parent_reset();
	fake_clock_start();
	max_files_rlimit.rlim_cur = 1;

	__real_replace_child(3);

	if (fake_slot_log[3].spawns != 1 || fake_sleeps != 0)
		BUG("spawn: a refill went on after its spawn stopped the run");
	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != EXIT_NO_FDS)
		BUG("spawn: a spawn past the fd limit did not stop the run");
}

/* A stop that lands while the refill sleeps between attempts gets no
 * further attempt: the check comes after the sleep as well as before
 * the first. */
static void refill_stops_when_the_run_stops_mid_backoff(enum stop_kind how)
{
	fake_parent_reset();
	fake_clock_start();
	fake_fork_fail[3] = FAKE_FORK_FAIL_ALWAYS;
	stopping_how = how;
	fake_sleep_hook = stop_the_run;

	__real_replace_child(3);

	if (fake_slot_log[3].forks != 1)
		BUG("spawn: a refill forked again after the run stopped mid-backoff");
}

/* The same for the fill: a spawn that stopped the run ends the call
 * uncounted and without a backoff, so no stall deadline is armed for it,
 * and the barrier stays shut. */
static void fill_stops_at_a_spawn_that_stopped_the_run(void)
{
	fake_parent_reset();
	fake_clock_start();
	max_files_rlimit.rlim_cur = 1;
	fill_all_but(3, 1);

	fork_children();

	if (fake_slot_log[3].spawns != 1 || fake_sleeps != 0)
		BUG("spawn: a fill went on after its spawn stopped the run");
	if (spawn_stall_deadline != 0)
		BUG("spawn: a spawn that stopped the run was counted as a fork failure");
	if (BARRIER_OPEN)
		BUG("spawn: a fill that stopped the run opened the barrier");
}

/* And a stop that lands while the fill sleeps between attempts: no
 * further attempt, and the barrier stays shut. */
static void fill_stops_when_the_run_stops_mid_backoff(enum stop_kind how)
{
	fake_parent_reset();
	fake_clock_start();
	fill_all_but(3, 1);
	fake_fork_fail[3] = FAKE_FORK_FAIL_ALWAYS;
	stopping_how = how;
	fake_sleep_hook = stop_the_run;

	fork_children();

	if (fake_slot_log[3].forks != 1)
		BUG("spawn: a fill forked again after the run stopped mid-backoff");
	if (BARRIER_OPEN)
		BUG("spawn: a fill that was stopped mid-backoff opened the barrier");
}

void spawn_self_check(void);
void spawn_self_check(void)
{
	enum stop_kind how;

	barrier_opens_once_every_slot_fills();
	throttled_fill_yields_after_each_spawn();
	throttled_fill_carries_on_past_a_parked_slot();
	barrier_opens_when_every_empty_slot_is_parked();
	failing_slot_is_skipped_for_one_call();
	throttled_fill_does_not_yield_for_a_skipped_slot();
	drain_stays_off_unless_asked_for();
	drain_count_carries_across_calls();
	spawn_success_restarts_the_drain_count();
	stalled_fill_opens_the_barrier_at_five_seconds();
	spawn_success_restarts_the_stall_deadline();
	replace_child_leaves_the_stall_deadline_alone();
	refill_stops_at_a_spawn_that_stopped_the_run();
	fill_stops_at_a_spawn_that_stopped_the_run();
	for (how = STOP_EXIT_REASON; how <= STOP_SPAWN_NO_MORE; how++) {
		refill_forks_nothing_into_a_stopping_run(how);
		refill_stops_when_the_run_stops_mid_backoff(how);
		fill_stops_when_the_run_stops_mid_backoff(how);
	}

	/* Leave no pids or counts for later suites. */
	fake_parent_reset();
}
