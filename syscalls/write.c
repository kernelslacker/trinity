/*
 * SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf, size_t, count)
 */
#include <stdlib.h>
#include "arch.h"	// page_size
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

static void sanitise_write(struct syscallrecord *rec)
{
	unsigned int size;
	void *ptr;

	if (RAND_BOOL())
		size = 1;
	else
		size = rnd() % page_size;

	ptr = malloc(size);
	if (ptr == NULL)
		return;

	generate_rand_bytes(ptr, size);

	rec->a2 = (unsigned long) ptr;
	rec->a3 = size;
}

static void post_write(struct syscallrecord *rec)
{
	freeptr(&rec->a2);
}

struct syscallentry syscall_write = {
	.name = "write",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buf",
	.arg2type = ARG_NON_NULL_ADDRESS,
	.arg3name = "count",
	.arg3type = ARG_LEN,
	.flags = NEED_ALARM,
	.sanitise = sanitise_write,
	.post     = post_write,
};

/*
 * SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec, unsigned long, vlen)
 */

struct syscallentry syscall_writev = {
	.name = "writev",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "vec",
	.arg2type = ARG_IOVEC,
	.arg3name = "vlen",
	.arg3type = ARG_IOVECLEN,
	.flags = NEED_ALARM,
};


/*
 * SYSCALL_DEFINE(pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t po>
 */

static void sanitise_pwrite64(struct syscallrecord *rec)
{
	sanitise_write(rec);

retry_pos:
	if ((int) rec->a4 < 0) {
		rec->a4 = rand64();
		goto retry_pos;
	}
}

struct syscallentry syscall_pwrite64 = {
	.name = "pwrite64",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "count",
	.arg3type = ARG_LEN,
	.arg4name = "pos",
	.flags = NEED_ALARM,
	.sanitise = sanitise_pwrite64,
	.post     = post_write,
};


/*
 * SYSCALL_DEFINE5(pwritev, unsigned long, fd, const struct iovec __user *, vec,
	 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)
 */

struct syscallentry syscall_pwritev = {
	.name = "pwritev",
	.num_args = 5,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "vec",
	.arg2type = ARG_IOVEC,
	.arg3name = "vlen",
	.arg3type = ARG_IOVECLEN,
	.arg4name = "pos_l",
	.arg5name = "pos_h",
	.flags = NEED_ALARM,
};

/*
 * SYSCALL_DEFINE5(pwritev2, unsigned long, fd, const struct iovec __user *, vec,
	 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h,
	 int, flags)
 */

static unsigned long pwritev2_flags[] = {
	RWF_HIPRI, RWF_DSYNC, RWF_SYNC,
};

struct syscallentry syscall_pwritev2 = {
	.name = "pwritev2",
	.num_args = 6,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "vec",
	.arg2type = ARG_IOVEC,
	.arg3name = "vlen",
	.arg3type = ARG_IOVECLEN,
	.arg4name = "pos_l",
	.arg5name = "pos_h",
	.arg6name = "flags",
	.arg6type = ARG_LIST,
	.arg6list = ARGLIST(pwritev2_flags),
	.flags = NEED_ALARM,
};
