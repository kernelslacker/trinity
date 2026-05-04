/*
 *SYSCALL_DEFINE2(clock_adjtime, const clockid_t, which_clock,
 *		struct timex __user *, utx)
 */
#include <sys/timex.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static unsigned long clock_ids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME, CLOCK_REALTIME_ALARM,
	CLOCK_BOOTTIME_ALARM, CLOCK_TAI,
};

static unsigned long clock_adj_modes[] = {
	ADJ_OFFSET, ADJ_FREQUENCY, ADJ_MAXERROR, ADJ_ESTERROR,
	ADJ_STATUS, ADJ_TIMECONST, ADJ_SETOFFSET, ADJ_MICRO,
	ADJ_NANO, ADJ_TICK,
};

static void sanitise_clock_adjtime(struct syscallrecord *rec)
{
	struct timex *tx;

	tx = (struct timex *) get_writable_address(sizeof(*tx));
	memset(tx, 0, sizeof(*tx));

	tx->modes = RAND_ARRAY(clock_adj_modes);

	switch (tx->modes) {
	case ADJ_OFFSET:
		tx->offset = (rand() % 1024001) - 512000;
		break;
	case ADJ_FREQUENCY:
		tx->freq = (rand32() % 67108865) - 33554432;
		break;
	case ADJ_MAXERROR:
		tx->maxerror = rand() % 1000000;
		break;
	case ADJ_ESTERROR:
		tx->esterror = rand() % 1000000;
		break;
	case ADJ_STATUS:
		tx->status = rand() & 0xff;
		break;
	case ADJ_TIMECONST:
		tx->constant = rand() % 11;
		break;
	case ADJ_TICK:
		tx->tick = 9000 + (rand() % 2001);
		break;
	case ADJ_SETOFFSET:
		tx->time.tv_sec = (rand() % 3) - 1;
		tx->time.tv_usec = rand() % 1000000;
		break;
	}

	rec->a2 = (unsigned long) tx;
}

static void post_clock_adjtime(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < TIME_OK || ret > TIME_ERROR)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_clock_adjtime = {
	.name = "clock_adjtime",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "which_clock", [1] = "utx" },
	.arg_params[0].list = ARGLIST(clock_ids),
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_clock_adjtime,
	.post = post_clock_adjtime,
};
