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

static void sanitise_write(struct syscallrecord *rec)
{
	if (rand_bool())
		rec->a3 = 1;
	else
		rec->a3 = rand() % page_size;
}

struct syscallentry syscall_write = {
	.name = "write",
	.num_args = 3,
	.sanitise = sanitise_write,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buf",
	.arg2type = ARG_NON_NULL_ADDRESS,
	.arg3name = "count",
	.arg3type = ARG_LEN,
	.flags = NEED_ALARM,
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

retry_pos:
	if ((int) rec->a4 < 0) {
		rec->a4 = rand64();
		goto retry_pos;
	}
}

struct syscallentry syscall_pwrite64 = {
	.name = "pwrite64",
	.num_args = 4,
	.sanitise = sanitise_pwrite64,
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
