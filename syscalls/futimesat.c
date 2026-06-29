/*
 * SYSCALL_DEFINE3(futimesat, int, dfd, const char __user *, filename,
	 struct timeval __user *, utimes)
 */
#include <sys/time.h>
#include <stdio.h>
#include "pathnames.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

/* Roughly "near now" in seconds since the epoch -- chosen so the
 * value lands inside the kernel's valid tv_sec range without needing
 * a syscall to clock_gettime() at sanitise time. */
#define NEAR_NOW_SEC	1700000000L
#define FAR_FUTURE_SEC	4000000000L

#define NR_TESTFILES 4		/* mirror fds/testfiles.c */

static void fill_valid_tv(struct timeval *tv, int bucket)
{
	switch (bucket) {
	case 0:
		/* near-now: jitter +/- 1 day */
		tv->tv_sec = NEAR_NOW_SEC + (long)(rnd_modulo_u32(172800)) - 86400L;
		tv->tv_usec = rnd_modulo_u32(1000000);
		return;
	case 1:
		/* far past (kernel accepts negative tv_sec) */
		tv->tv_sec = -(long) rnd_u32();
		tv->tv_usec = rnd_modulo_u32(1000000);
		return;
	default:
		/* far future */
		tv->tv_sec = FAR_FUTURE_SEC + (long) rnd_u32();
		tv->tv_usec = rnd_modulo_u32(1000000);
		return;
	}
}

static void fill_invalid_tv(struct timeval *tv)
{
	tv->tv_sec = rnd_modulo_u32(2000000000);
	/* tv_usec must be < 1e6; the kernel returns EINVAL otherwise. */
	tv->tv_usec = 1000000L + rnd_modulo_u32(1000000);
}

static void sanitise_futimesat(struct syscallrecord *rec)
{
	struct timeval *tv;
	unsigned int bucket;
	unsigned int i;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a2, but it
	 * is almost never a real file, so futimesat returns ENOENT at
	 * the path walk before reaching the per-fs timestamp setattr.
	 * Half the draws pin a2 to an absolute trinity-owned testfile
	 * so the call penetrates the VFS path; an absolute path
	 * ignores the dfd in a1, so no valid dirfd is needed.  The
	 * other half preserves the random pathname so the ENOENT /
	 * -ENOTDIR reject arms stay exercised.  The a3 timeval logic
	 * below runs in both branches.
	 */
	if (rec->a2 && rnd_modulo_u32(2) == 0) {
		char *path = get_testfile_path();

		if (path != NULL)
			rec->a2 = (unsigned long) path;
	}

	bucket = rnd_modulo_u32(100);

	if (bucket < 20) {
		/* NULL utimes -- kernel uses current time. */
		rec->a3 = 0;
		return;
	}

	tv = (struct timeval *) get_writable_address(sizeof(*tv) * 2);
	if (tv == NULL)
		return;

	if (bucket < 45) {
		/* both near-now valid */
		fill_valid_tv(&tv[0], 0);
		fill_valid_tv(&tv[1], 0);
	} else if (bucket < 65) {
		/* both far-past or far-future */
		int b = RAND_BOOL() ? 1 : 2;
		fill_valid_tv(&tv[0], b);
		fill_valid_tv(&tv[1], b);
	} else if (bucket < 80) {
		/* both intentionally-invalid tv_usec */
		fill_invalid_tv(&tv[0]);
		fill_invalid_tv(&tv[1]);
	} else if (bucket < 90) {
		/* mixed valid + invalid */
		fill_valid_tv(&tv[0], 0);
		fill_invalid_tv(&tv[1]);
	} else {
		/* random */
		for (i = 0; i < 2; i++) {
			tv[i].tv_sec = rnd_modulo_u32(2000000000);
			tv[i].tv_usec = rnd_modulo_u32(1000000);
		}
	}

	rec->a3 = (unsigned long) tv;

	/*
	 * utimes (a3) is the curated [atime, mtime] pair the kernel reads.
	 * ARG_ADDRESS slots are subject to the post-sanitise blanket address
	 * scrub, which relocates the pointer to a fresh pool page; the plain
	 * _out variant would publish the new pointer without the curated
	 * bytes and the kernel would read pool garbage for tv_sec/tv_usec,
	 * defeating the near-now / far / invalid-usec buckets above.  _inout
	 * relocates AND memcpys the payload, so the scrub no-ops on a3 and
	 * the kernel sees the real timeval pair we built.  Only reached on
	 * the curated branch -- the NULL-utimes early-return and the
	 * gwa-failure early-return both bail before this point, so a3 == 0
	 * and a3 == unwritten paths are untouched.
	 */
	avoid_shared_buffer_inout(&rec->a3, sizeof(struct timeval) * 2);
}

struct syscallentry syscall_futimesat = {
	.name = "futimesat",
	.group = GROUP_TIME,
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_ADDRESS },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "utimes" },
	.sanitise = sanitise_futimesat,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
};
