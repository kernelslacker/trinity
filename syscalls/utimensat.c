/*
 * SYSCALL_DEFINE4(utimensat, int, dfd, const char __user *, filename,
	 struct timespec __user *, utimes, int, flags)
 */
#include <fcntl.h>
#include <time.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

/* From linux/stat.h - special nsec values for utimensat */
#ifndef UTIME_NOW
#define UTIME_NOW  ((1l << 30) - 1l)
#endif
#ifndef UTIME_OMIT
#define UTIME_OMIT ((1l << 30) - 2l)
#endif

#define NEAR_NOW_SEC	1700000000L
#define FAR_FUTURE_SEC	4000000000L

enum ts_bucket {
	TS_UTIME_NOW,
	TS_UTIME_OMIT,
	TS_NEAR_NOW,
	TS_FAR_PAST,
	TS_FAR_FUTURE,
	TS_INVALID_NSEC,
	TS_RANDOM,
};

static void fill_one_timespec(struct timespec *ts, enum ts_bucket b)
{
	switch (b) {
	case TS_UTIME_NOW:
		ts->tv_sec = 0;
		ts->tv_nsec = UTIME_NOW;
		return;
	case TS_UTIME_OMIT:
		ts->tv_sec = 0;
		ts->tv_nsec = UTIME_OMIT;
		return;
	case TS_NEAR_NOW:
		ts->tv_sec = NEAR_NOW_SEC + (long)(rnd_modulo_u32(172800)) - 86400L;
		ts->tv_nsec = rnd_modulo_u32(1000000000);
		return;
	case TS_FAR_PAST:
		ts->tv_sec = -(long) rnd_u32();
		ts->tv_nsec = rnd_modulo_u32(1000000000);
		return;
	case TS_FAR_FUTURE:
		ts->tv_sec = FAR_FUTURE_SEC + (long) rnd_u32();
		ts->tv_nsec = rnd_modulo_u32(1000000000);
		return;
	case TS_INVALID_NSEC:
		ts->tv_sec = rnd_modulo_u32(2000000000);
		/* >= 1e9 and not UTIME_NOW / UTIME_OMIT */
		ts->tv_nsec = 1000000000L + rnd_modulo_u32(1000000);
		return;
	default:
		ts->tv_sec = rnd_modulo_u32(2000000000);
		ts->tv_nsec = rnd_modulo_u32(1000000000);
		return;
	}
}

static void sanitise_utimensat(struct syscallrecord *rec)
{
	struct timespec *ts;
	unsigned int bucket;

	/* flags: AT_SYMLINK_NOFOLLOW on ~30%, off otherwise. */
	if (rnd_modulo_u32(10) < 3)
		rec->a4 = (unsigned long) AT_SYMLINK_NOFOLLOW;
	else
		rec->a4 = 0;

	bucket = rnd_modulo_u32(100);

	if (bucket < 15) {
		/* NULL utimes -- set both to current time. */
		rec->a3 = 0;
		return;
	}

	ts = (struct timespec *) get_writable_address(sizeof(*ts) * 2);
	if (ts == NULL)
		return;

	if (bucket < 30) {
		fill_one_timespec(&ts[0], TS_UTIME_NOW);
		fill_one_timespec(&ts[1], TS_UTIME_NOW);
	} else if (bucket < 40) {
		fill_one_timespec(&ts[0], TS_UTIME_OMIT);
		fill_one_timespec(&ts[1], TS_UTIME_OMIT);
	} else if (bucket < 50) {
		/* one NOW, one OMIT (order randomised) */
		if (RAND_BOOL()) {
			fill_one_timespec(&ts[0], TS_UTIME_NOW);
			fill_one_timespec(&ts[1], TS_UTIME_OMIT);
		} else {
			fill_one_timespec(&ts[0], TS_UTIME_OMIT);
			fill_one_timespec(&ts[1], TS_UTIME_NOW);
		}
	} else if (bucket < 70) {
		fill_one_timespec(&ts[0], TS_NEAR_NOW);
		fill_one_timespec(&ts[1], TS_NEAR_NOW);
	} else if (bucket < 85) {
		enum ts_bucket b = RAND_BOOL() ? TS_FAR_PAST : TS_FAR_FUTURE;
		fill_one_timespec(&ts[0], b);
		fill_one_timespec(&ts[1], b);
	} else if (bucket < 95) {
		fill_one_timespec(&ts[0], TS_INVALID_NSEC);
		fill_one_timespec(&ts[1], TS_INVALID_NSEC);
	} else {
		fill_one_timespec(&ts[0], TS_RANDOM);
		fill_one_timespec(&ts[1], TS_RANDOM);
	}

	rec->a3 = (unsigned long) ts;

	/*
	 * utimes (a3) is the curated input the kernel reads: the timespec
	 * pair above encodes UTIME_NOW/UTIME_OMIT, near-now, far past/future,
	 * and the invalid-nsec edges we want to push at the syscall.  a3 is
	 * ARG_ADDRESS, so the post-sanitise blanket address scrub relocates
	 * the slot to a fresh pool page; the plain _out variant would publish
	 * the new pointer without the curated bytes and the kernel would read
	 * pool garbage for (tv_sec, tv_nsec).  _inout relocates AND memcpys
	 * the payload, so the scrub no-ops on a3 and the kernel sees the real
	 * timespec[2] we built above.  The NULL-utimes early-return branch
	 * above does not reach here, so this only fires on the curated path.
	 */
	avoid_shared_buffer_inout(&rec->a3, sizeof(struct timespec) * 2);
}

struct syscallentry syscall_utimensat = {
	.name = "utimensat",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_ADDRESS },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "utimes", [3] = "flags" },
	.sanitise = sanitise_utimensat,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
};
