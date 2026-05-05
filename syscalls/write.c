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

/*
 * Snapshot of the (buf, count) pair the post handler needs, captured at
 * sanitise time and parked in rec->post_state -- a slot the syscall ABI
 * does not expose, so a sibling syscall scribbling rec->a2/a3 between
 * syscall return and post_write() running cannot redirect us at a foreign
 * buffer or hand the count-bound validator the wrong length.  Shared by
 * write(2) and pwrite64(2): both register post_write.
 */
struct write_post_state {
	unsigned long buf;
	unsigned long count;
};

static void sanitise_write(struct syscallrecord *rec)
{
	unsigned int size;
	void *ptr;
	struct write_post_state *snap;

	/* Last line of defense: don't write to stdin/stdout/stderr. */
	if (rec->a1 <= 2)
		rec->a1 = get_random_fd();

	if (RAND_BOOL())
		size = 1;
	else
		size = rand() % page_size;

	ptr = zmalloc(size);
	if (ptr == NULL)
		return;

	generate_rand_bytes(ptr, size);

	rec->a2 = (unsigned long) ptr;
	rec->a3 = size;
	/*
	 * Snapshot (buf, count) for the post handler -- a2/a3 may be
	 * scribbled by a sibling syscall before post_write() runs, so the
	 * count-bound validator must read count from the post-state-private
	 * slot rather than the sibling-stomp-vulnerable rec->a3.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->buf = (unsigned long) ptr;
	snap->count = size;
	rec->post_state = (unsigned long) snap;
}

static void post_write(struct syscallrecord *rec)
{
	struct write_post_state *snap =
		(struct write_post_state *) rec->post_state;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_write: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * STRONG-VAL count bound: write(2) / pwrite64(2) on success return
	 * the number of bytes successfully written (0..count); failure
	 * returns -1UL.  A retval > count on a non-(-1UL) return is a
	 * structural ABI regression -- a sign-extension tear in the syscall
	 * return path, a torn write of count by a parallel signal-restart
	 * path, or -errno leaking through the success slot.  Read count from
	 * snap->count, not rec->a3: snap lives in the post-state-private
	 * slot the syscall ABI does not expose, so it is immune to the
	 * sibling-stomp class that can scribble rec->aN between syscall
	 * return and post entry.  Mirrors the lgetxattr / fgetxattr / getxattr
	 * size-bound shape with snap->count instead of snap->size.
	 */
	if ((long) rec->retval == -1L)
		goto skip_bound;
	if (rec->retval > snap->count) {
		outputerr("corrupt write retval %lu > count %lu\n",
			  rec->retval, snap->count);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

skip_bound:
	/* fall through */

out_free:
	rec->a2 = 0;
	deferred_free_enqueue((void *) snap->buf, NULL);
	snap->buf = 0;
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
