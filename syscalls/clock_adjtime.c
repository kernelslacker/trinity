/*
 *SYSCALL_DEFINE2(clock_adjtime, const clockid_t, which_clock,
 *		struct timex __user *, utx)
 */
#include <sys/timex.h>
#include <string.h>
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

static unsigned long clock_ids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME, CLOCK_REALTIME_ALARM,
	CLOCK_BOOTTIME_ALARM, CLOCK_TAI,
};

/*
 * Read-only (modes == 0) is a distinct legality bucket: it does not
 * write any timekeeping state but must round-trip the full timex back
 * to userspace, so the read/copy path needs coverage independent of
 * the per-mode write paths.
 */
static unsigned long clock_adj_modes[] = {
	0, ADJ_OFFSET, ADJ_FREQUENCY, ADJ_MAXERROR, ADJ_ESTERROR,
	ADJ_STATUS, ADJ_TIMECONST, ADJ_SETOFFSET, ADJ_MICRO,
	ADJ_NANO, ADJ_TICK,
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

static void sanitise_clock_adjtime(struct syscallrecord *rec)
{
	struct timex *tx;

	rec->a1 = pick_clockid();

	tx = (struct timex *) get_writable_address(sizeof(*tx));
	if (tx == NULL)
		return;
	memset(tx, 0, sizeof(*tx));

	tx->modes = RAND_ARRAY(clock_adj_modes);

	switch (tx->modes) {
	case 0:
		/* Read-only: leave the rest of the timex zeroed. */
		break;
	case ADJ_OFFSET:
		tx->offset = (rnd_modulo_u32(1024001)) - 512000;
		break;
	case ADJ_FREQUENCY:
		tx->freq = (rand32() % 67108865) - 33554432;
		break;
	case ADJ_MAXERROR:
		tx->maxerror = rnd_modulo_u32(1000000);
		break;
	case ADJ_ESTERROR:
		tx->esterror = rnd_modulo_u32(1000000);
		break;
	case ADJ_STATUS:
		tx->status = rnd_u32() & 0xff;
		break;
	case ADJ_TIMECONST:
		tx->constant = rnd_modulo_u32(11);
		break;
	case ADJ_TICK:
		tx->tick = 9000 + (rnd_modulo_u32(2001));
		break;
	case ADJ_SETOFFSET:
		tx->time.tv_sec = (rnd_modulo_u32(3)) - 1;
		tx->time.tv_usec = rnd_modulo_u32(1000000);
		break;
	}

	rec->a2 = (unsigned long) tx;
	avoid_shared_buffer_inout(&rec->a2, sizeof(struct timex));
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
	.rettype = RET_BORING,
};
