/*
 * SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
 */
#include <sys/signalfd.h>
#include <sys/uio.h>
#include "arch.h"
#include "fd.h"
#include "files.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

#include "kernel/fs.h"
static void sanitise_read(struct syscallrecord *rec)
{
	bool typed_size = false;

	/*
	 * ~30% of the time, override the generic ARG_FD pick with a
	 * draw from the pollable typed-fd pools so the kernel's
	 * readable-state path for eventfd / timerfd / signalfd /
	 * inotify / fanotify actually gets exercised, and size the
	 * read at that fd type's natural width so it returns data
	 * instead of EINVAL'ing on a bogus count.  If the typed pool
	 * is empty get_typed_fd() falls back to a generic random fd;
	 * either way we keep going.
	 */
	if (rnd_modulo_u32(10) < 3) {
		static const enum argtype pollable[] = {
			ARG_FD_PIPE,
			ARG_FD_EVENTFD,
			ARG_FD_TIMERFD,
			ARG_FD_SIGNALFD,
			ARG_FD_INOTIFY,
			ARG_FD_FANOTIFY,
			ARG_FD_SOCKET,
		};
		enum argtype t = pollable[rnd_modulo_u32(ARRAY_SIZE(pollable))];
		int fd = get_typed_fd(t);

		if (fd >= 0) {
			rec->a1 = fd;
			switch (t) {
			case ARG_FD_EVENTFD:
			case ARG_FD_TIMERFD:
				rec->a3 = sizeof(uint64_t);
				typed_size = true;
				break;
			case ARG_FD_SIGNALFD:
				rec->a3 = sizeof(struct signalfd_siginfo);
				typed_size = true;
				break;
			case ARG_FD_INOTIFY:
				rec->a3 = 256;
				typed_size = true;
				break;
			default:
				/* pipe / socket / fanotify: leave the
				 * generic page-sized shape below. */
				break;
			}
		}
	}

	rec->a2 = (unsigned long) get_non_null_address();
	if (!typed_size) {
		if (RAND_BOOL())
			rec->a3 = rnd_modulo_u32(page_size);
		else
			rec->a3 = page_size;
	}
	avoid_shared_buffer_out(&rec->a2, rec->a3);
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
	.rettype = RET_NUM_BYTES,
};


/*
 * SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec, unsigned long>
 */

static void sanitise_readv(struct syscallrecord *rec)
{
	struct iovec *iov = (struct iovec *) rec->a2;

	/*
	 * Mirror the bias step in sanitise_read: ~30% of the time
	 * override the generic ARG_FD pick with a draw from the
	 * pollable typed-fd pools so the kernel's readable-state
	 * path for eventfd / timerfd / signalfd / inotify / fanotify
	 * gets exercised via readv as well as plain read.  For the
	 * size-strict fd types the kernel rejects any iovec whose
	 * total length doesn't match the natural width, so collapse
	 * the array to a single entry at that width; pipe / socket /
	 * fanotify accept the generic multi-entry random shape and
	 * are left alone.  On typed-pool empty (-1) fall through
	 * without publishing a stale fd.  Skip the override entirely
	 * if ARG_IOVEC handed us a degenerate (NULL / vlen == 0)
	 * shape -- the collapse needs a usable iov[0].
	 */
	if (iov != NULL && rec->a3 != 0 && rnd_modulo_u32(10) < 3) {
		static const enum argtype pollable[] = {
			ARG_FD_PIPE,
			ARG_FD_EVENTFD,
			ARG_FD_TIMERFD,
			ARG_FD_SIGNALFD,
			ARG_FD_INOTIFY,
			ARG_FD_FANOTIFY,
			ARG_FD_SOCKET,
		};
		enum argtype t = pollable[rnd_modulo_u32(ARRAY_SIZE(pollable))];
		int fd = get_typed_fd(t);

		if (fd >= 0) {
			rec->a1 = fd;
			switch (t) {
			case ARG_FD_EVENTFD:
			case ARG_FD_TIMERFD:
				rec->a3 = 1;
				iov[0].iov_len = sizeof(uint64_t);
				break;
			case ARG_FD_SIGNALFD:
				rec->a3 = 1;
				iov[0].iov_len = sizeof(struct signalfd_siginfo);
				break;
			case ARG_FD_INOTIFY:
				rec->a3 = 1;
				iov[0].iov_len = 256;
				break;
			default:
				/* pipe / socket / fanotify: leave the
				 * generic multi-entry shape. */
				break;
			}
		}
	}

	scrub_iovec_for_kernel_write((struct iovec *)rec->a2, rec->a3);
}

struct syscallentry syscall_readv = {
	.name = "readv",
	.num_args = 3,
	.sanitise = sanitise_readv,
	.argtype = { [0] = ARG_FD, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN },
	.argname = { [0] = "fd", [1] = "vec", [2] = "vlen" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.rettype = RET_NUM_BYTES,
};

/*
 * SYSCALL_DEFINE(pread64)(unsigned int fd, char __user *buf, size_t count, loff_t pos)
 */

static void sanitise_pread64(struct syscallrecord *rec)
{
	if (rnd_modulo_u32(100) < 25) {
		int fd = get_rand_pagecache_fd();
		if (fd >= 0)
			rec->a1 = fd;
	}

	rec->a3 = rnd_modulo_u32(page_size);
	rec->a4 = rand64() & 0x7fffffffffffffffULL;
	avoid_shared_buffer_out(&rec->a2, rec->a3);
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
	.rettype = RET_NUM_BYTES,
};

/*
 * SYSCALL_DEFINE5(preadv, unsigned long, fd, const struct iovec __user *, vec,
	 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)
 */

static void sanitise_preadv(struct syscallrecord *rec)
{
	if (rnd_modulo_u32(100) < 25) {
		int fd = get_rand_pagecache_fd();
		if (fd >= 0)
			rec->a1 = fd;
	}

	/* Generate a valid file position (non-negative loff_t). */
	rec->a5 = 0;	/* pos_h: keep offset < 4GB */
	rec->a4 = rand64() & 0x7fffffff;	/* pos_l: non-negative */

	scrub_iovec_for_kernel_write((struct iovec *)rec->a2, rec->a3);
}

struct syscallentry syscall_preadv = {
	.name = "preadv",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN },
	.argname = { [0] = "fd", [1] = "vec", [2] = "vlen", [3] = "pos_l", [4] = "pos_h" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_preadv,
	.group = GROUP_VFS,
	.rettype = RET_NUM_BYTES,
};

/*
 * SYSCALL_DEFINE5(preadv2, unsigned long, fd, const struct iovec __user *, vec,
	 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h,
	 int, flags)
 */
static unsigned long preadv2_flags[] = {
	RWF_HIPRI, RWF_DSYNC, RWF_SYNC,
	RWF_NOWAIT, RWF_APPEND, RWF_NOAPPEND,
	RWF_ATOMIC, RWF_DONTCACHE, RWF_NOSIGNAL,
};

static void sanitise_preadv2(struct syscallrecord *rec)
{
	if (rnd_modulo_u32(100) < 25) {
		int fd = get_rand_pagecache_fd();
		if (fd >= 0)
			rec->a1 = fd;
	}

	if (RAND_BOOL()) {
		/* pos == -1: use current file position */
		rec->a4 = (unsigned long) -1;
		rec->a5 = (unsigned long) -1;
	} else {
		rec->a5 = 0;
		rec->a4 = rand64() & 0x7fffffff;
	}

	scrub_iovec_for_kernel_write((struct iovec *)rec->a2, rec->a3);
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
	.rettype = RET_NUM_BYTES,
};
