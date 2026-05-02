/*
 * SYSCALL_DEFINE1(time, time_t __user *, tloc)
 */
#include <time.h>
#include "shm.h"
#include "random.h"
#include "sanitise.h"
#include "trinity.h"

static void sanitise_time(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(time_t));
}

/*
 * Oracle: sys_time returns current wall-clock time in seconds since the
 * Epoch -- the same value we get from clock_gettime(CLOCK_REALTIME).
 * Both are ultimately served by the same timekeeping subsystem, so a
 * meaningful divergence between the two reads taken back-to-back from
 * userspace points at a real ABI break: a sign-extension bug in the
 * compat path, a 32-bit y2038 wrap, a tloc-copy-back that wrote stale
 * stack, or the syscall returning a cached value from a stale vsyscall
 * page after a clock-jump.
 *
 * Tolerance is +/-5 seconds.  The two reads aren't atomic with respect
 * to each other: scheduler delay between sys_time returning and us
 * calling clock_gettime, plus NTP slew across the gap, can legitimately
 * shift the second sample by a second or two.  A real ABI break
 * (truncation, wrap, sign extension) puts the values days or years
 * apart, well outside this window.
 *
 * Sample only successful returns; sanitised tloc pointers can produce
 * -EFAULT and that's not an oracle violation.  ONE_IN(100) keeps the
 * extra clock_gettime cost in line with the rest of the oracle family.
 */
static void post_time(struct syscallrecord *rec)
{
	struct timespec ts;
	long syscall_t, real_t, diff;

	if (!ONE_IN(100))
		return;

	syscall_t = (long) rec->retval;
	if (syscall_t <= 0)
		return;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return;

	real_t = (long) ts.tv_sec;
	diff = syscall_t - real_t;

	if (diff < -5 || diff > 5) {
		output(0, "time oracle: returned %ld but clock_gettime=%ld (diff=%ld)\n",
		       syscall_t, real_t, diff);
		__atomic_add_fetch(&shm->stats.time_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_time = {
	.name = "time",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "tloc" },
	.sanitise = sanitise_time,
	.post = post_time,
};
