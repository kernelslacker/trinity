/*
 * SYSCALL_DEFINE2(clock_settime, const clockid_t, which_clock, const struct timespec __user *, tp)
 *
 * return 0 for success, or -1 for failure (in which case errno is set appropriately).
 */
#include <time.h>
#include "pids.h"
#include "sanitise.h"
#include "utils.h"
#include "clock-common.h"

#include "kernel/time.h"
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
	rec->a1 = pick_clockid();

	/*
	 * a2 (tp) is typed ARG_TIMESPEC; the generator publishes a
	 * writable pool buffer with bucketed tv_sec/tv_nsec shapes
	 * (boundaries, overflow corners, garbage tv_nsec) for us.
	 */
}

struct syscallentry syscall_clock_settime = {
	.name = "clock_settime",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_TIMESPEC },
	.argname = { [0] = "which_clock", [1] = "tp" },
	.arg_params[0].list = ARGLIST(clock_ids),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEEDS_ROOT | REEXEC_SANITISE_OK,
	.sanitise = sanitise_clock_settime,
};
