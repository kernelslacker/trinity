/*
 * SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf, size_t, count)
 */
#include <sys/uio.h>
#include <string.h>
#include "arch.h"	// page_size
#include "fd.h"
#include "files.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fs.h"

static void sanitise_write(struct syscallrecord *rec)
{
	unsigned int size;
	void *ptr;
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

	/* Belt-and-suspenders: keep the stderr capture memfd (and other
	 * protected fds) out of rec->a1 so a fuzz-induced write at a
	 * fabricated lseek offset can't extend it to multi-GB and turn
	 * the next SIGABRT-handler bug-log drain into a host-swamping
	 * write.  Also catches get_random_fd() above happening to draw
	 * a protected fd. */
	reroll_protected_fd_arg(&rec->a1);

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

	/*
	 * The kernel reads the buffer, and the blanket scrub would move a
	 * heap one into the writable pool without its bytes: move it with
	 * them.  The heap original stays the one rec_own() frees.
	 */
	rec->a2 = (unsigned long) ptr;
	avoid_shared_buffer_inout(&rec->a2, size);
	rec->a3 = size;

	/*
	 * Capture the genuine kernel-input buffer at sanitise time, before
	 * any sibling can stomp rec->a2; the carrier drain after the call
	 * frees it unconditionally, retfd-rejected and killed-EXTRA_FORK
	 * calls included.
	 */
	rec_own(rec, ptr);
}

struct syscallentry syscall_write = {
	.name = "write",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "buf", [2] = "count" },
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.sanitise = sanitise_write,
	.group = GROUP_VFS_IO,
	.bound_arg = 3,
	/* count (a3): enforce_count_bound() holds the return to the count
	 * the kernel was handed, which chain substitution or a RedQueen pin
	 * may have rewritten after the sanitiser drew its own. */
	.arg_snapshot_mask = (1u << 2),
	.rettype = RET_NUM_BYTES,
};

/*
 * SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec, unsigned long, vlen)
 */

static void sanitise_writev(struct syscallrecord *rec)
{
	void *iov = (void *) rec->a2;

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
					iovec_set_entry(iov, 0,
							(unsigned long) buf,
							sizeof(uint64_t),
							rec->do32bit);
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
				iovec_set_entry_len(iov, 0, RAND_ARRAY(tsizes),
						    rec->do32bit);
			}
		} else if (roll < 40) {
			int sfd = get_typed_fd(ARG_FD_SIGNALFD);
			if (sfd >= 0) {
				static const unsigned int ssizes[] = {
					0, 1, 7, 8, 128,
				};
				rec->a1 = (unsigned long) sfd;
				rec->a3 = 1;
				iovec_set_entry_len(iov, 0, RAND_ARRAY(ssizes),
						    rec->do32bit);
			}
		}
	}

	/* Last line of defense: don't write to stdin/stdout/stderr. */
	if (rec->a1 <= 2)
		rec->a1 = get_random_fd();
	reroll_protected_fd_arg(&rec->a1);
}

struct syscallentry syscall_writev = {
	.name = "writev",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_IOVEC_IN, [2] = ARG_IOVECLEN },
	.argname = { [0] = "fd", [1] = "vec", [2] = "vlen" },
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.sanitise = sanitise_writev,
	.group = GROUP_VFS_IO,
	.rettype = RET_NUM_BYTES,
};


/*
 * SYSCALL_DEFINE(pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t po>
 */

static void sanitise_pwrite64(struct syscallrecord *rec)
{
	sanitise_write(rec);
	if (rnd_modulo_u32(100) < 25) {
		int fd = get_rand_writeable_pagecache_fd();
		if (fd >= 0)
			rec->a1 = fd;
	}
	rec->a4 = rand64() & 0x7fffffffffffffffULL;
}

struct syscallentry syscall_pwrite64 = {
	.name = "pwrite64",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "buf", [2] = "count", [3] = "pos" },
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.sanitise = sanitise_pwrite64,
	.group = GROUP_VFS_IO,
	.bound_arg = 3,
	/* count (a3), as for write. */
	.arg_snapshot_mask = (1u << 2),
	.rettype = RET_NUM_BYTES,
};


/*
 * SYSCALL_DEFINE5(pwritev, unsigned long, fd, const struct iovec __user *, vec,
	 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)
 */

static void sanitise_pwritev(struct syscallrecord *rec)
{
	uint64_t v;

	if (rnd_modulo_u32(100) < 25) {
		int fd = get_rand_writeable_pagecache_fd();
		if (fd >= 0)
			rec->a1 = fd;
	}
	if (rec->a1 <= 2)
		rec->a1 = get_random_fd();
	reroll_protected_fd_arg(&rec->a1);
	v = rand64() & 0x7fffffffffffffffULL;
	rec->a4 = v & 0xffffffff;
	rec->a5 = (v >> 32) & 0xffffffff;
}

struct syscallentry syscall_pwritev = {
	.name = "pwritev",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_IOVEC_IN, [2] = ARG_IOVECLEN },
	.argname = { [0] = "fd", [1] = "vec", [2] = "vlen", [3] = "pos_l", [4] = "pos_h" },
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.sanitise = sanitise_pwritev,
	.group = GROUP_VFS_IO,
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
	uint64_t v;

	if (rnd_modulo_u32(100) < 25) {
		int fd = get_rand_writeable_pagecache_fd();
		if (fd >= 0)
			rec->a1 = fd;
	}
	if (rec->a1 <= 2)
		rec->a1 = get_random_fd();
	reroll_protected_fd_arg(&rec->a1);
	if (RAND_BOOL()) {
		rec->a4 = (unsigned long) -1;
		rec->a5 = (unsigned long) -1;
	} else {
		v = rand64() & 0x7fffffffffffffffULL;
		rec->a4 = v & 0xffffffff;
		rec->a5 = (v >> 32) & 0xffffffff;
	}
}

struct syscallentry syscall_pwritev2 = {
	.name = "pwritev2",
	.num_args = 6,
	.argtype = { [0] = ARG_FD, [1] = ARG_IOVEC_IN, [2] = ARG_IOVECLEN, [5] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "vec", [2] = "vlen", [3] = "pos_l", [4] = "pos_h", [5] = "flags" },
	.arg_params[5].list = ARGLIST(pwritev2_flags),
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.sanitise = sanitise_pwritev2,
	.group = GROUP_VFS_IO,
	.rettype = RET_NUM_BYTES,
};
