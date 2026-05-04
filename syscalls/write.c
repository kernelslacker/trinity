/*
 * SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf, size_t, count)
 */
#include <stdlib.h>
#include "arch.h"	// page_size
#include "fd.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"
#include "utils.h"

static void sanitise_write(struct syscallrecord *rec)
{
	unsigned int size;
	void *ptr;

	/* Last line of defense: don't write to stdin/stdout/stderr. */
	if (rec->a1 <= 2)
		rec->a1 = get_random_fd();

	if (RAND_BOOL())
		size = 1;
	else
		size = rand() % page_size;

	ptr = malloc(size);
	if (ptr == NULL)
		return;

	generate_rand_bytes(ptr, size);

	rec->a2 = (unsigned long) ptr;
	rec->a3 = size;
	/* Snapshot for the post handler -- a2 may be scribbled by a sibling
	 * syscall before post_write() runs. */
	rec->post_state = (unsigned long) ptr;
}

static void post_write(struct syscallrecord *rec)
{
	void *buf = (void *) rec->post_state;

	if (buf == NULL)
		return;

	if (looks_like_corrupted_ptr(buf)) {
		outputerr("post_write: rejected suspicious buf=%p (pid-scribbled?)\n", buf);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a2 = 0;
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_write = {
	.name = "write",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "buf", [2] = "count" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_write,
	.post     = post_write,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec, unsigned long, vlen)
 */

static void sanitise_writev(struct syscallrecord *rec)
{
	if (rec->a1 <= 2)
		rec->a1 = get_random_fd();
}

struct syscallentry syscall_writev = {
	.name = "writev",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN },
	.argname = { [0] = "fd", [1] = "vec", [2] = "vlen" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_writev,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE(pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t po>
 */

static void sanitise_pwrite64(struct syscallrecord *rec)
{
	sanitise_write(rec);
	rec->a4 = rand64() & 0x7fffffffffffffffULL;
}

struct syscallentry syscall_pwrite64 = {
	.name = "pwrite64",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "buf", [2] = "count", [3] = "pos" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_pwrite64,
	.post     = post_write,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE5(pwritev, unsigned long, fd, const struct iovec __user *, vec,
	 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)
 */

static void sanitise_pwritev(struct syscallrecord *rec)
{
	if (rec->a1 <= 2)
		rec->a1 = get_random_fd();
	rec->a5 = 0;
	rec->a4 = rand64() & 0x7fffffff;
}

struct syscallentry syscall_pwritev = {
	.name = "pwritev",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN },
	.argname = { [0] = "fd", [1] = "vec", [2] = "vlen", [3] = "pos_l", [4] = "pos_h" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_pwritev,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE5(pwritev2, unsigned long, fd, const struct iovec __user *, vec,
	 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h,
	 int, flags)
 */

static unsigned long pwritev2_flags[] = {
	RWF_HIPRI, RWF_DSYNC, RWF_SYNC,
};

static void sanitise_pwritev2(struct syscallrecord *rec)
{
	if (rec->a1 <= 2)
		rec->a1 = get_random_fd();
	if (RAND_BOOL()) {
		rec->a4 = (unsigned long) -1;
		rec->a5 = (unsigned long) -1;
	} else {
		rec->a5 = 0;
		rec->a4 = rand64() & 0x7fffffff;
	}
}

struct syscallentry syscall_pwritev2 = {
	.name = "pwritev2",
	.num_args = 6,
	.argtype = { [0] = ARG_FD, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN, [5] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "vec", [2] = "vlen", [3] = "pos_l", [4] = "pos_h", [5] = "flags" },
	.arg_params[5].list = ARGLIST(pwritev2_flags),
	.flags = NEED_ALARM,
	.sanitise = sanitise_pwritev2,
	.group = GROUP_VFS,
};
