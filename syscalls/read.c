/*
 * SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
 */
#include <stdlib.h>
#include <string.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "compat.h"

static void sanitise_read(struct syscallrecord *rec)
{
	rec->a2 = (unsigned long) get_non_null_address();
	if (RAND_BOOL())
		rec->a3 = rnd() % page_size;
	else
		rec->a3 = page_size;
}

struct syscallentry syscall_read = {
	.name = "read",
	.num_args = 3,
	.sanitise = sanitise_read,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "count",
	.arg3type = ARG_LEN,
	.flags = NEED_ALARM,
};


/*
 * SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec, unsigned long>
 */

struct syscallentry syscall_readv = {
	.name = "readv",
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
 * SYSCALL_DEFINE(pread64)(unsigned int fd, char __user *buf, size_t count, loff_t pos)
 */

static void sanitise_pread64(struct syscallrecord *rec)
{
	rec->a3 = rnd() % page_size;

retry_pos:
	if ((int) rec->a4 < 0) {
		rec->a4 = rand64();
		goto retry_pos;
	}
}

struct syscallentry syscall_pread64 = {
	.name = "pread64",
	.num_args = 4,
	.sanitise = sanitise_pread64,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "count",
	.arg3type = ARG_LEN,
	.arg4name = "pos",
	.flags = NEED_ALARM,
};

/*
 * SYSCALL_DEFINE5(preadv, unsigned long, fd, const struct iovec __user *, vec,
	 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)
 */

struct syscallentry syscall_preadv = {
	.name = "preadv",
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
 * SYSCALL_DEFINE5(preadv2, unsigned long, fd, const struct iovec __user *, vec,
	 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h,
	 int, flags)
 */
static unsigned long preadv2_flags[] = {
	RWF_HIPRI, RWF_DSYNC, RWF_SYNC,
};

struct syscallentry syscall_preadv2 = {
	.name = "preadv2",
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
	.arg6list = ARGLIST(preadv2_flags),
	.flags = NEED_ALARM,
};
