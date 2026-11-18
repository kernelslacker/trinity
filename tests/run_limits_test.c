/*
 * Self-check for the run's stop reasons: panic() (main/loop.c) keeps a
 * failure over any clean stop that lands after it, and a run-ending stop
 * over an epoch restart, so a limit check falling due on the same tick
 * cannot turn a failed or finished run into another epoch.
 */

#include <stdbool.h>
#include <time.h>

#include "debug.h"		/* BUG */
#include "exit.h"
#include "main-internal.h"	/* check_run_limits */
#include "params.h"
#include "shm.h"
#include "stats_ring.h"		/* parent_stats */
#include "tables.h"		/* syscalls_todo */
#include "trinity.h"		/* panic, reset_epoch_state */
#include "utils-macros.h"	/* ARRAY_SIZE */

#include "fake_parent.h"

static const enum exit_reasons clean_stops[] = {
	EXIT_EPOCH_DONE,
	EXIT_REACHED_COUNT,
	EXIT_SIGINT,
	EXIT_USER_REQUEST,
	EXIT_MAX_RUNTIME,
};

static void failure_outlives_clean_stops(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(clean_stops); i++) {
		fake_parent_reset();
		panic(EXIT_KERNEL_TAINTED);
		panic(clean_stops[i]);

		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) !=
		    EXIT_KERNEL_TAINTED)
			BUG("panic: a clean stop replaced a failure");
		if (reset_epoch_state())
			BUG("panic: a failed run went on to another epoch");
	}
}

static void failure_replaces_clean_stop(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(clean_stops); i++) {
		fake_parent_reset();
		panic(clean_stops[i]);
		panic(EXIT_KERNEL_TAINTED);

		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) !=
		    EXIT_KERNEL_TAINTED)
			BUG("panic: a failure did not replace a clean stop");
	}
}

/* An epoch restart claims only a running run: one landing with or after
 * a stop that ends the run must not start another epoch. */
static void run_stop_outlives_epoch_restart(void)
{
	static const enum exit_reasons run_stops[] = {
		EXIT_REACHED_COUNT,
		EXIT_SIGINT,
		EXIT_USER_REQUEST,
		EXIT_MAX_RUNTIME,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(run_stops); i++) {
		fake_parent_reset();
		panic(run_stops[i]);
		panic(EXIT_EPOCH_DONE);

		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) !=
		    run_stops[i])
			BUG("panic: an epoch restart replaced a run-ending stop");
		if (reset_epoch_state())
			BUG("panic: a finished run went on to another epoch");
	}
}

/*
 * The tick the kernel taints: taint_check() publishes EXIT_KERNEL_TAINTED
 * before check_run_limits() runs, and a limit falls due on that same tick.
 */
static void taint_tick_keeps_its_reason(void)
{
	static const struct {
		const char *what;
		unsigned long todo;
		unsigned long iterations;
		unsigned int timeout;
		unsigned int runtime;
	} due[] = {
		{ "-N", 100, 0, 0, 0 },
		{ "--epoch-iterations", 0, 100, 0, 0 },
		{ "--epoch-timeout", 0, 0, 5, 0 },
		{ "--max-runtime", 0, 0, 0, 5 },
	};
	struct timespec epoch_start;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(due); i++) {
		fake_parent_reset();
		syscalls_todo = due[i].todo;
		epoch_iterations = due[i].iterations;
		epoch_timeout = due[i].timeout;
		max_runtime = due[i].runtime;
		parent_stats.op_count = 100;
		parent_stats.total_op_count = 100;
		parent_stats.epoch_start_op_count = 0;
		clock_gettime(CLOCK_MONOTONIC, &epoch_start);
		epoch_start.tv_sec -= 10;

		panic(EXIT_KERNEL_TAINTED);
		check_run_limits(&epoch_start, &epoch_start);

		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) !=
		    EXIT_KERNEL_TAINTED) {
			fprintf(stderr, "limit due: %s\n", due[i].what);
			BUG("run limits: a limit due on the taint tick replaced the taint");
		}
		if (reset_epoch_state())
			BUG("run limits: the taint tick restarted the fleet");
	}
}

/*
 * -N counts the whole run: the first epoch ends at its iteration limit
 * below the run's limit, and the second takes the run past it with fewer
 * ops of its own than the limit.
 */
static void count_spans_epochs(void)
{
	struct timespec epoch_start;

	fake_parent_reset();
	clock_gettime(CLOCK_MONOTONIC, &epoch_start);
	syscalls_todo = 100;
	epoch_iterations = 80;
	epoch_timeout = 0;
	max_runtime = 0;
	parent_stats.total_op_count = 80;
	parent_stats.epoch_start_op_count = 0;
	parent_stats.op_count = 80;

	check_run_limits(&epoch_start, &epoch_start);
	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) !=
	    EXIT_EPOCH_DONE)
		BUG("run limits: the first epoch did not end at its iteration limit");
	if (!reset_epoch_state())
		BUG("run limits: refused to start the second epoch");

	/* What stats_ring_drain_all() derives 40 ops into the new epoch. */
	parent_stats.total_op_count = 120;
	parent_stats.op_count = parent_stats.total_op_count -
				parent_stats.epoch_start_op_count;

	check_run_limits(&epoch_start, &epoch_start);
	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) !=
	    EXIT_REACHED_COUNT)
		BUG("run limits: -N lost the ops of an earlier epoch");
}

/*
 * --max-runtime bounds the whole run under a reason of its own: an
 * --epoch-iterations boundary a minute in only restarts the epoch, and
 * the deadline still falls an hour after the run began, ten seconds
 * into the next epoch.
 */
static void max_runtime_spans_epochs(void)
{
	struct timespec run_start, epoch_start;

	fake_parent_reset();
	syscalls_todo = 0;
	epoch_iterations = 50;
	epoch_timeout = 0;
	max_runtime = 3600;
	clock_gettime(CLOCK_MONOTONIC, &run_start);
	run_start.tv_sec -= 60;
	epoch_start = run_start;
	parent_stats.total_op_count = 50;
	parent_stats.epoch_start_op_count = 0;
	parent_stats.op_count = 50;

	check_run_limits(&run_start, &epoch_start);
	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) !=
	    EXIT_EPOCH_DONE)
		BUG("run limits: an iteration boundary under --max-runtime did not end the epoch");
	if (!reset_epoch_state())
		BUG("run limits: an iteration boundary under --max-runtime ended the run");

	clock_gettime(CLOCK_MONOTONIC, &epoch_start);
	epoch_start.tv_sec -= 10;
	run_start.tv_sec -= 3600;
	parent_stats.total_op_count = 60;
	parent_stats.op_count = parent_stats.total_op_count -
				parent_stats.epoch_start_op_count;

	check_run_limits(&run_start, &epoch_start);
	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) !=
	    EXIT_MAX_RUNTIME)
		BUG("run limits: --max-runtime counted from the epoch, not the run");
}

void run_limits_self_check(void);
void run_limits_self_check(void)
{
	/* The epoch timeout's checkpoint has no home here. */
	bool saved_flags[] = { no_warm_start, no_kcov_warm_start,
			       no_cmp_hints_warm_start, no_chain_warm_start };

	no_warm_start = no_kcov_warm_start = true;
	no_cmp_hints_warm_start = no_chain_warm_start = true;

	failure_outlives_clean_stops();
	failure_replaces_clean_stop();
	run_stop_outlives_epoch_restart();
	taint_tick_keeps_its_reason();
	count_spans_epochs();
	max_runtime_spans_epochs();

	syscalls_todo = 0;
	epoch_iterations = 0;
	epoch_timeout = 0;
	max_runtime = 0;
	parent_stats.op_count = 0;
	parent_stats.total_op_count = 0;
	parent_stats.epoch_start_op_count = 0;
	no_warm_start = saved_flags[0];
	no_kcov_warm_start = saved_flags[1];
	no_cmp_hints_warm_start = saved_flags[2];
	no_chain_warm_start = saved_flags[3];
	fake_parent_reset();
}
