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

static unsigned long clock_ids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME,
};

/*
 * Local copies of the kernel's POSIX CPU clock encoding from
 * include/linux/posix-timers.h.  Not in UAPI but the encoding has been
 * stable since the syscalls landed.
 */
#ifndef CLOCKFD
#define CLOCKFD				3
#define CPUCLOCK_PERTHREAD_MASK		4
#define CPUCLOCK_PROF			0
#define CPUCLOCK_VIRT			1
#define CPUCLOCK_SCHED			2
#define MAKE_PROCESS_CPUCLOCK(pid, clk)	\
	((~(clockid_t)(pid) << 3) | (clockid_t)(clk))
#define MAKE_THREAD_CPUCLOCK(tid, clk)	\
	MAKE_PROCESS_CPUCLOCK((tid), (clk) | CPUCLOCK_PERTHREAD_MASK)
#define FD_TO_CLOCKID(fd)		\
	((~(clockid_t)(fd) << 3) | CLOCKFD)
#endif

/*
 * clock_settime needs CAP_SYS_TIME and only REALTIME / TAI are settable,
 * so the unprivileged caller will mostly EPERM.  That is fine: the goal
 * is to keep the validation path warm without burning every draw on the
 * one or two privileged clockids.  Bias common, but still send the
 * CPU/dynamic/invalid shapes through occasionally for the dispatch
 * rejection path.
 */
static const unsigned long pick_clockid_common[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_TAI,
	CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE,
	CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM,
	CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID,
};

static const int pick_clockid_cpuwhich[] = {
	CPUCLOCK_PROF, CPUCLOCK_VIRT, CPUCLOCK_SCHED,
};

static unsigned long pick_clockid(void)
{
	unsigned int roll = rnd_modulo_u32(100);
	int w;
	pid_t pid;

	if (roll < 50)
		return pick_clockid_common[rnd_modulo_u32(
			ARRAY_SIZE(pick_clockid_common))];

	w = pick_clockid_cpuwhich[rnd_modulo_u32(
		ARRAY_SIZE(pick_clockid_cpuwhich))];

	if (roll < 70)
		return MAKE_PROCESS_CPUCLOCK((pid_t) get_pid(), w);

	if (roll < 80) {
		pid = mypid();
		if (RAND_BOOL())
			return MAKE_THREAD_CPUCLOCK(pid, w);
		return MAKE_PROCESS_CPUCLOCK(pid, w);
	}

	if (roll < 90)
		return FD_TO_CLOCKID(rnd_modulo_u32(1024));

	return (unsigned long) (rnd_u32() | (1u << 20));
}

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
