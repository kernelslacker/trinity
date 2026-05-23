/*
 * SYSCALL_DEFINE4(clock_nanosleep, const clockid_t, which_clock, int, flags,
	const struct timespec __user *, rqtp,
	struct timespec __user *, rmtp)
 *
 * On successfully sleeping for the requested interval, clock_nanosleep() returns 0.
 * If the call is interrupted by a signal handler or  encounters  an  error,
 *  then it returns one of the positive error number listed in ERRORS.
 */

#include <time.h>
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

static unsigned long clock_nanosleep_which[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_BOOTTIME, CLOCK_TAI,
	CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM,
};

static unsigned long clock_nanosleep_flags[] = {
	TIMER_ABSTIME,
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

static void sanitise_clock_nanosleep(struct syscallrecord *rec)
{
	struct timespec *ts;
	int abstime;

	rec->a1 = pick_clockid();

	/*
	 * Force a 50/50 flags bucket: relative (0) or absolute
	 * (TIMER_ABSTIME).  The ARG_LIST generator picks at least one bit
	 * from the values array, which with a single-element {TIMER_ABSTIME}
	 * means the relative path never ran from random fuzz.
	 */
	abstime = RAND_BOOL();
	rec->a2 = abstime ? TIMER_ABSTIME : 0;

	ts = (struct timespec *) get_writable_address(sizeof(*ts));
	if (ts == NULL)
		return;

	if (abstime) {
		/*
		 * Absolute mode with a past time returns immediately, which
		 * never exercises the hrtimer wait path.  Read the same clock
		 * and add a tiny delta so the kernel actually has to schedule
		 * the sleep before it expires.  Fall back to a near-epoch
		 * shape if the clock is unreadable (CPU/dynamic/invalid).
		 */
		struct timespec now;

		if (clock_gettime((clockid_t) rec->a1, &now) == 0) {
			long delta = 1000L * (long) (1 + rnd_modulo_u32(500));
			ts->tv_sec = now.tv_sec;
			ts->tv_nsec = now.tv_nsec + delta;
			if (ts->tv_nsec >= 1000000000L) {
				ts->tv_sec += ts->tv_nsec / 1000000000L;
				ts->tv_nsec %= 1000000000L;
			}
		} else {
			ts->tv_sec = 0;
			ts->tv_nsec = rnd_modulo_u32(1000);
		}
	} else {
		/* Relative: keep durations tiny so we don't block the fuzzer. */
		ts->tv_sec = 0;
		switch (rnd_modulo_u32(4)) {
		case 0: ts->tv_nsec = 0; break;
		case 1: ts->tv_nsec = 1; break;
		case 2: ts->tv_nsec = rnd_modulo_u32(1000); break;
		default: ts->tv_nsec = rnd_modulo_u32(1000000); break;
		}
	}

	rec->a3 = (unsigned long) ts;

	/*
	 * rmtp (a4) is the kernel's "remaining time on EINTR" output buffer:
	 * if the sleep is interrupted, the kernel writes the unslept residual
	 * timespec there.  Random pool can land it inside an alloc_shared
	 * region, so scrub.
	 */
	avoid_shared_buffer_out(&rec->a4, sizeof(struct timespec));
}

static void post_clock_nanosleep(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret != 0 && ret != -1L) {
		output(0, "post_clock_nanosleep: rejected retval %ld outside {0, -1}\n", ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_clock_nanosleep = {
	.name = "clock_nanosleep",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_OP, [1] = ARG_LIST, [3] = ARG_ADDRESS },
	.argname = { [0] = "which_clock", [1] = "flags", [2] = "rqtp", [3] = "rmtp" },
	.arg_params[0].list = ARGLIST(clock_nanosleep_which),
	.arg_params[1].list = ARGLIST(clock_nanosleep_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_clock_nanosleep,
	.post = post_clock_nanosleep,
};
