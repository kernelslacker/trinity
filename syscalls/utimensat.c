/*
 * SYSCALL_DEFINE4(utimensat, int, dfd, const char __user *, filename,
	 struct timespec __user *, utimes, int, flags)
 */
#include <fcntl.h>
#include <time.h>
#include "random.h"
#include "sanitise.h"

/* From linux/stat.h - special nsec values for utimensat */
#ifndef UTIME_NOW
#define UTIME_NOW  ((1l << 30) - 1l)
#endif
#ifndef UTIME_OMIT
#define UTIME_OMIT ((1l << 30) - 2l)
#endif

static unsigned long utimensat_flags[] = {
	AT_SYMLINK_NOFOLLOW,
};

static void sanitise_utimensat(struct syscallrecord *rec)
{
	struct timespec *ts;
	unsigned int i;

	/* NULL utimes means "set both to current time" - allow that sometimes */
	if (ONE_IN(8)) {
		rec->a3 = 0;
		return;
	}

	ts = (struct timespec *) get_writable_address(sizeof(*ts) * 2);

	for (i = 0; i < 2; i++) {
		switch (rand() % 4) {
		case 0:
			ts[i].tv_sec = 0;
			ts[i].tv_nsec = UTIME_NOW;
			break;
		case 1:
			ts[i].tv_sec = 0;
			ts[i].tv_nsec = UTIME_OMIT;
			break;
		default:
			ts[i].tv_sec = rand() % 2000000000;
			ts[i].tv_nsec = rand() % 1000000000;
			break;
		}
	}

	rec->a3 = (unsigned long) ts;
}

struct syscallentry syscall_utimensat = {
	.name = "utimensat",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "utimes", [3] = "flags" },
	.arg_params[3].list = ARGLIST(utimensat_flags),
	.sanitise = sanitise_utimensat,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
};
