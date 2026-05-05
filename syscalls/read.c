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
#include "trinity.h"
#include "compat.h"

static void sanitise_read(struct syscallrecord *rec)
{
	rec->a2 = (unsigned long) get_non_null_address();
	if (RAND_BOOL())
		rec->a3 = rand() % page_size;
	else
		rec->a3 = page_size;
	avoid_shared_buffer(&rec->a2, rec->a3);
}

struct syscallentry syscall_read = {
	.name = "read",
	.num_args = 3,
	.sanitise = sanitise_read,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "buf", [2] = "count" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.bound_arg = 3,
};


/*
 * SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec, unsigned long>
 */

struct syscallentry syscall_readv = {
	.name = "readv",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN },
	.argname = { [0] = "fd", [1] = "vec", [2] = "vlen" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE(pread64)(unsigned int fd, char __user *buf, size_t count, loff_t pos)
 */

static void sanitise_pread64(struct syscallrecord *rec)
{
	rec->a3 = rand() % page_size;
	rec->a4 = rand64() & 0x7fffffffffffffffULL;
	avoid_shared_buffer(&rec->a2, rec->a3);
}

struct syscallentry syscall_pread64 = {
	.name = "pread64",
	.num_args = 4,
	.sanitise = sanitise_pread64,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "buf", [2] = "count", [3] = "pos" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.bound_arg = 3,
};

/*
 * SYSCALL_DEFINE5(preadv, unsigned long, fd, const struct iovec __user *, vec,
	 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)
 */

static void sanitise_preadv(struct syscallrecord *rec)
{
	/* Generate a valid file position (non-negative loff_t). */
	rec->a5 = 0;	/* pos_h: keep offset < 4GB */
	rec->a4 = rand64() & 0x7fffffff;	/* pos_l: non-negative */
}

struct syscallentry syscall_preadv = {
	.name = "preadv",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN },
	.argname = { [0] = "fd", [1] = "vec", [2] = "vlen", [3] = "pos_l", [4] = "pos_h" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_preadv,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE5(preadv2, unsigned long, fd, const struct iovec __user *, vec,
	 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h,
	 int, flags)
 */
static unsigned long preadv2_flags[] = {
	RWF_HIPRI, RWF_DSYNC, RWF_SYNC,
};

static void sanitise_preadv2(struct syscallrecord *rec)
{
	if (RAND_BOOL()) {
		/* pos == -1: use current file position */
		rec->a4 = (unsigned long) -1;
		rec->a5 = (unsigned long) -1;
	} else {
		rec->a5 = 0;
		rec->a4 = rand64() & 0x7fffffff;
	}
}

struct syscallentry syscall_preadv2 = {
	.name = "preadv2",
	.num_args = 6,
	.argtype = { [0] = ARG_FD, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN, [5] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "vec", [2] = "vlen", [3] = "pos_l", [4] = "pos_h", [5] = "flags" },
	.arg_params[5].list = ARGLIST(preadv2_flags),
	.flags = NEED_ALARM,
	.sanitise = sanitise_preadv2,
	.group = GROUP_VFS,
};
