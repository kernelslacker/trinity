/*
 * SYSCALL_DEFINE2(gettimeofday, struct timeval __user *, tv, struct timezone __user *, tz)
 */
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include "shm.h"
#include "random.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_gettimeofday(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(struct timeval));
	avoid_shared_buffer(&rec->a2, sizeof(struct timezone));
}

/*
 * Oracle: sys_gettimeofday writes the current wall-clock time into the
 * caller's struct timeval -- ultimately the same timekeeping subsystem
 * that backs clock_gettime(CLOCK_REALTIME).  A meaningful divergence
 * between the value the kernel just copied out and a back-to-back
 * clock_gettime read points at a real ABI break: copy_to_user landing
 * past or before the tv slot, a torn write to the user buffer, a stale
 * vsyscall page after a clock-jump, or a sign-extension bug on the
 * compat path.
 *
 * Tolerance is +/-5 seconds.  The two reads aren't atomic with respect
 * to each other: scheduler delay between sys_gettimeofday returning and
 * us calling clock_gettime, plus NTP slew across the gap, can
 * legitimately shift the second sample by a second or two.  A real ABI
 * break (truncation, wrap, sign extension, wrong slot) puts the values
 * days or years apart, well outside this window.
 *
 * We deliberately don't compare tv_usec.  Without atomic reads the
 * tolerance window would have to be impractically narrow to catch a
 * real break without drowning in false positives from the gap between
 * the two samples.
 *
 * We memcpy the timeval into a local before inspecting it so a
 * concurrent thread can't mutate the user buffer between our checks
 * (TOCTOU).  Sample only successful returns with a non-NULL tv;
 * sanitised pointers can produce -EFAULT and that's not an oracle
 * violation.  ONE_IN(100) keeps the extra clock_gettime cost in line
 * with the rest of the oracle family.
 */
static void post_gettimeofday(struct syscallrecord *rec)
{
	struct timeval local_tv;
	struct timespec ts;
	long diff;

	if (!ONE_IN(100))
		return;

	if (rec->retval != 0)
		return;

	if (rec->a1 == 0)
		return;

	{
		void *tv = (void *)(unsigned long) rec->a1;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a1. */
		if (looks_like_corrupted_ptr(tv)) {
			outputerr("post_gettimeofday: rejected suspicious tv=%p (pid-scribbled?)\n",
				  tv);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	memcpy(&local_tv, (void *) rec->a1, sizeof(local_tv));

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return;

	diff = (long) local_tv.tv_sec - (long) ts.tv_sec;

	if (diff < -5 || diff > 5) {
		output(0, "gettimeofday oracle: tv.tv_sec=%ld but clock_gettime=%ld (diff=%ld)\n",
		       (long) local_tv.tv_sec, (long) ts.tv_sec, diff);
		__atomic_add_fetch(&shm->stats.gettimeofday_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_gettimeofday = {
	.name = "gettimeofday",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "tv", [1] = "tz" },
	.sanitise = sanitise_gettimeofday,
	.rettype = RET_ZERO_SUCCESS,
	.post = post_gettimeofday,
};
