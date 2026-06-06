/*
 * SYSCALL_DEFINE2(clock_settime, const clockid_t, which_clock, const struct timespec __user *, tp)
 *
 * return 0 for success, or -1 for failure (in which case errno is set appropriately).
 */
#include <limits.h>
#include <time.h>
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"
#include "compat.h"
#include "clock-common.h"

static unsigned long clock_ids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME,
};

/*
 * clock_settime needs CAP_SYS_TIME and only REALTIME / TAI are settable,
 * so the unprivileged caller will mostly EPERM.  That is fine: the goal
 * is to keep the validation path warm without burning every draw on the
 * one or two privileged clockids.  pick_clockid() biases common, but
 * still sends the CPU/dynamic/invalid shapes through occasionally for
 * the dispatch rejection path.
 */
static void sanitise_clock_settime(struct syscallrecord *rec)
{
	struct timespec *ts;

	rec->a1 = pick_clockid();

	ts = (struct timespec *) get_writable_address(sizeof(*ts));
	if (ts == NULL)
		return;

	/*
	 * Seven roughly-equal shape buckets covering the legal range,
	 * boundaries, and the invalid-tv_nsec validation path.
	 */
	switch (rnd_modulo_u32(7)) {
	case 0:	/* epoch */
		ts->tv_sec = 0;
		ts->tv_nsec = 0;
		break;
	case 1:	/* tiny (1 ns) */
		ts->tv_sec = 0;
		ts->tv_nsec = 1;
		break;
	case 2:	/* one second */
		ts->tv_sec = 1;
		ts->tv_nsec = 0;
		break;
	case 3:	/* near-current (small offset) */
		ts->tv_sec = time(NULL) + (rnd_modulo_u32(120)) - 60;
		ts->tv_nsec = rnd_modulo_u32(1000000000);
		break;
	case 4:	/* far future / INT_MAX corners */
		if (RAND_BOOL())
			ts->tv_sec = INT_MAX;
		else
			ts->tv_sec = (time_t) time(NULL) +
				(time_t) (365L * 86400L * 50L);	/* +50y */
		ts->tv_nsec = rnd_modulo_u32(1000000000);
		break;
	case 5:	/* negative tv_sec */
		ts->tv_sec = -(time_t) (1 + rnd_modulo_u32(1 << 20));
		ts->tv_nsec = rnd_modulo_u32(1000000000);
		break;
	default:	/* garbage tv_nsec (>= 1e9) — must EINVAL */
		ts->tv_sec = (time_t) rand32();
		ts->tv_nsec = 1000000000 + (long) rnd_modulo_u32(1000000000);
		break;
	}

	rec->a2 = (unsigned long) ts;
}

struct syscallentry syscall_clock_settime = {
	.name = "clock_settime",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "which_clock", [1] = "tp" },
	.arg_params[0].list = ARGLIST(clock_ids),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_clock_settime,
};
