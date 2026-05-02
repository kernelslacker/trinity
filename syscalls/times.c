/*
 * SYSCALL_DEFINE1(times, struct tms __user *, tbuf)
 */
#include <string.h>
#include <sys/times.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_times(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(struct tms));
}

/*
 * Oracle: times(&buf) returns the wall-clock value in clock_t ticks since
 * boot and copies a struct tms holding the calling process's cumulative CPU
 * accounting -- tms_utime/tms_stime for self, tms_cutime/tms_cstime for
 * already-reaped children -- out to the user buffer.  All five values are
 * monotonic counters: the wall-clock return advances with the timer tick
 * and never rewinds, and each tms_* field is a per-task accumulator the
 * kernel only ever increments.  A second call moments later must see every
 * field at least as large as the first.  A decrease is therefore not a
 * benign race but a corruption signal pointing at one of:
 *
 *   - copy_to_user mis-write: the kernel produced the right values but the
 *     destination address was partially mapped or wrong, leaving torn or
 *     stale bytes in the user buffer.
 *   - 32-bit-on-64-bit compat sign-extension bug: a regression in the
 *     compat copy could sign-extend a clock_t that should be unsigned-
 *     widened, flipping a small positive count into a huge negative one
 *     that compares as decreasing on the next read.
 *   - struct-layout mismatch on 32-on-64 emulation: adjacent fields
 *     shifted, so e.g. tms_stime lands in the tms_utime slot and a
 *     subsequent read with the right layout shows a smaller value where
 *     the larger one used to sit.
 *   - sibling-thread scribble of the user receive buffer between the
 *     syscall return and our post-hook re-read.
 *
 * TOCTOU defeat: snapshot the user buffer to a stack-local before the re-
 * call so a sibling thread cannot scribble on rec->a1 between the original
 * syscall return and the comparison.  Re-issue times() into a separate
 * stack buffer; if the re-call returns (clock_t)-1 give up rather than
 * report a false divergence.  Compare all five values with no early-return
 * so multi-field corruption surfaces in a single sample, and emit one log
 * line carrying both 5-tuples so the operator sees the full divergence
 * shape at once.  Bump the anomaly counter once per sample regardless of
 * how many fields decreased.  Sample one in a hundred to stay in line with
 * the rest of the oracle family.
 *
 * No benign drift sources here: both reads are forward-only counters from
 * the same task, so any decrease is real.  The audit anchor stands purely
 * to catch the corruption shapes above.
 */
static void post_times(struct syscallrecord *rec)
{
	struct tms first, recall;
	clock_t r;

	if (!ONE_IN(100))
		return;

	if ((clock_t) rec->retval == (clock_t) -1)
		return;

	if (rec->a1 == 0)
		return;

	memcpy(&first, (struct tms *)(unsigned long) rec->a1, sizeof(first));

	r = times(&recall);
	if (r == (clock_t) -1)
		return;

	if (r < (clock_t) rec->retval ||
	    recall.tms_utime  < first.tms_utime  ||
	    recall.tms_stime  < first.tms_stime  ||
	    recall.tms_cutime < first.tms_cutime ||
	    recall.tms_cstime < first.tms_cstime) {
		output(0,
		       "[oracle:times] retval %ld vs %ld utime %ld vs %ld stime %ld vs %ld cutime %ld vs %ld cstime %ld vs %ld\n",
		       (long) (clock_t) rec->retval, (long) r,
		       (long) first.tms_utime,  (long) recall.tms_utime,
		       (long) first.tms_stime,  (long) recall.tms_stime,
		       (long) first.tms_cutime, (long) recall.tms_cutime,
		       (long) first.tms_cstime, (long) recall.tms_cstime);
		__atomic_add_fetch(&shm->stats.times_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_times = {
	.name = "times",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "tbuf" },
	.sanitise = sanitise_times,
	.post = post_times,
};
