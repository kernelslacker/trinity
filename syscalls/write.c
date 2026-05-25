/*
 * SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf, size_t, count)
 */
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include "arch.h"	// page_size
#include "fd.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
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
 *
 * Leading magic cookie because the heap-shape check on rec->post_state
 * is value-based only -- a sibling scribbling rec->post_state with any
 * heap-shaped 8-byte aligned pointer to a foreign allocation sails past
 * looks_like_corrupted_ptr() and the post handler then reads snap->count
 * from foreign bytes and free()s snap->buf as a foreign address; both
 * surface as the dominant __zmalloc -> malloc -> malloc_printerr ->
 * abort crash cluster.  Mirrors RECVMSG_POST_STATE_MAGIC at recv.c:103.
 * Padded to 32 bytes (48-byte glibc malloc chunk) so the snap does not
 * land in the 32-byte chunk bucket shared with size=1 bufs (the
 * RAND_BOOL branch below uses size=1 half the time) and with the small
 * post_state structs.  Bucket separation is defense-in-depth; the
 * cookie is the primary defense.
 */
#define WRITE_POST_STATE_MAGIC	0x5752495445504F53UL	/* "WRITEPOS" */
struct write_post_state {
	unsigned long magic;
	unsigned long buf;
	unsigned long count;
	unsigned long _bucket_pad;
};

static void sanitise_write(struct syscallrecord *rec)
{
	unsigned int size;
	void *ptr;
	struct write_post_state *snap;
	int forced_fd = -1;
	int forced_size = -1;
	bool eventfd_payload = false;

	/*
	 * Per-fd-type bias: the generic ARG_FD pool rarely picks the
	 * poll-style fd types, and the random RAND_BOOL ? 1 :
	 * rnd_modulo_u32(page_size) shape almost never lines up the
	 * ABI-mandated write width those types require.
	 *
	 *   - eventfd:  write() MUST be exactly 8 bytes carrying a u64
	 *               counter add; anything else returns -EINVAL and
	 *               the consumer-side poll-wakeup path never fires.
	 *   - timerfd / signalfd: read-only; write() returns -EINVAL
	 *               unconditionally.  Targeted small-size probes
	 *               exercise the per-fd-type write-reject hook.
	 *
	 * Roll once out of 100; on typed-pool empty (-1) fall through to
	 * the generic ARG_FD path so we never publish a stale fd.
	 */
	{
		unsigned int roll = rnd_modulo_u32(100);

		if (roll < 20) {
			int efd = get_typed_fd(ARG_FD_EVENTFD);
			if (efd >= 0) {
				forced_fd = efd;
				forced_size = sizeof(uint64_t);
				eventfd_payload = true;
			}
		} else if (roll < 30) {
			int tfd = get_typed_fd(ARG_FD_TIMERFD);
			if (tfd >= 0) {
				static const unsigned int tsizes[] = {
					0, 1, 7, 8, 9,
				};
				forced_fd = tfd;
				forced_size = RAND_ARRAY(tsizes);
			}
		} else if (roll < 40) {
			int sfd = get_typed_fd(ARG_FD_SIGNALFD);
			if (sfd >= 0) {
				static const unsigned int ssizes[] = {
					0, 1, 7, 8, 128,
				};
				forced_fd = sfd;
				forced_size = RAND_ARRAY(ssizes);
			}
		}
	}

	if (forced_fd >= 0)
		rec->a1 = (unsigned long) forced_fd;

	/* Last line of defense: don't write to stdin/stdout/stderr. */
	if (rec->a1 <= 2)
		rec->a1 = get_random_fd();

	if (forced_size >= 0)
		size = (unsigned int) forced_size;
	else if (RAND_BOOL())
		size = 1;
	else
		size = rnd_modulo_u32(page_size);

	ptr = zmalloc_tracked(size);
	if (ptr == NULL)
		return;

	if (eventfd_payload) {
		uint64_t val = rnd_u64();
		memcpy(ptr, &val, sizeof(val));
	} else {
		generate_rand_bytes(ptr, size);
	}

	rec->a2 = (unsigned long) ptr;
	rec->a3 = size;
	/*
	 * Snapshot (buf, count) for the post handler -- a2/a3 may be
	 * scribbled by a sibling syscall before post_write() runs, so the
	 * count-bound validator must read count from the post-state-private
	 * slot rather than the sibling-stomp-vulnerable rec->a3.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = WRITE_POST_STATE_MAGIC;
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
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * write_post_state -- the subsequent free(snap->buf) would feed
	 * a foreign address back to glibc and the count-bound check would
	 * compare retval against garbage.  Mirrors recv.c:212.
	 */
	if (snap->magic != WRITE_POST_STATE_MAGIC) {
		outputerr("post_write: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
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
	deferred_free_enqueue((void *) snap->buf);
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
	.bound_arg = 3,
	.rettype = RET_NUM_BYTES,
};

/*
 * SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec, unsigned long, vlen)
 */

static void sanitise_writev(struct syscallrecord *rec)
{
	struct iovec *iov = (struct iovec *) rec->a2;

	/*
	 * Per-fd-type bias: the generic ARG_FD pool rarely picks the
	 * poll-style fd types, and the random ARG_IOVEC shape almost
	 * never lines up the ABI-mandated writev widths those types
	 * require.
	 *
	 *   - eventfd:  writev() MUST deliver exactly 8 bytes total
	 *               carrying a u64 counter add; anything else
	 *               returns -EINVAL and the consumer-side poll-
	 *               wakeup path never fires.
	 *   - timerfd / signalfd: read-only; writev() returns -EINVAL
	 *               unconditionally.  Targeted small-size probes
	 *               exercise the per-fd-type write-reject hook,
	 *               distinct from the write(2) path covered by
	 *               sanitise_write.
	 *
	 * Roll once out of 100; on typed-pool empty (-1) fall through to
	 * the generic ARG_FD path so we never publish a stale fd.  Skip
	 * the override entirely if ARG_IOVEC handed us a degenerate
	 * (NULL / vlen==0) shape -- the collapse needs a usable iov[0].
	 */
	if (iov != NULL && rec->a3 != 0) {
		unsigned int roll = rnd_modulo_u32(100);

		if (roll < 20) {
			int efd = get_typed_fd(ARG_FD_EVENTFD);
			if (efd >= 0) {
				/*
				 * alloc_iovec() intentionally emits iov_base
				 * values that are not writable from Trinity:
				 * SHAPE_NULL, SHAPE_INVALID (0xdeadbeef), and
				 * map-backed shapes whose protections include
				 * PROT_NONE.  memcpy'ing into iov[0].iov_base
				 * faulted in the child before the kernel ever
				 * saw writev().  Drop the eventfd arm onto a
				 * known-writable buffer; on pool exhaustion
				 * skip the override and let the generic shape
				 * stand so a stale eventfd never gets paired
				 * with a sentinel base.
				 */
				void *buf = get_writable_struct(sizeof(uint64_t));
				if (buf != NULL) {
					uint64_t val = rnd_u64();

					rec->a1 = (unsigned long) efd;
					rec->a3 = 1;
					iov[0].iov_base = buf;
					iov[0].iov_len = sizeof(uint64_t);
					memcpy(buf, &val, sizeof(val));
				}
			}
		} else if (roll < 30) {
			int tfd = get_typed_fd(ARG_FD_TIMERFD);
			if (tfd >= 0) {
				static const unsigned int tsizes[] = {
					0, 1, 7, 8, 9,
				};
				rec->a1 = (unsigned long) tfd;
				rec->a3 = 1;
				iov[0].iov_len = RAND_ARRAY(tsizes);
			}
		} else if (roll < 40) {
			int sfd = get_typed_fd(ARG_FD_SIGNALFD);
			if (sfd >= 0) {
				static const unsigned int ssizes[] = {
					0, 1, 7, 8, 128,
				};
				rec->a1 = (unsigned long) sfd;
				rec->a3 = 1;
				iov[0].iov_len = RAND_ARRAY(ssizes);
			}
		}
	}

	/* Last line of defense: don't write to stdin/stdout/stderr. */
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
	.rettype = RET_NUM_BYTES,
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
	.bound_arg = 3,
	.rettype = RET_NUM_BYTES,
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
	.rettype = RET_NUM_BYTES,
};

/*
 * SYSCALL_DEFINE5(pwritev2, unsigned long, fd, const struct iovec __user *, vec,
	 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h,
	 int, flags)
 */

static unsigned long pwritev2_flags[] = {
	RWF_HIPRI, RWF_DSYNC, RWF_SYNC,
	RWF_NOWAIT, RWF_APPEND, RWF_NOAPPEND,
	RWF_ATOMIC, RWF_DONTCACHE, RWF_NOSIGNAL,
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
	.rettype = RET_NUM_BYTES,
};
