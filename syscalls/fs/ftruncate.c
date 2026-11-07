/*
 * SYSCALL_DEFINE2(ftruncate, unsigned int, fd, unsigned long, length)
 */
#include "fd.h"
#include "files.h"
#include "maps.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_ftruncate(struct syscallrecord *rec)
{
	/* Bias the fd toward the writable pagecache pool so the actual
	 * regular-file truncate paths fire instead of bouncing off the
	 * VFS prologue on pipes / sockets / read-only handles drawn from
	 * the broad ARG_FD pool.  Mirrors the positioned-write bias in
	 * write.c.  Applied BEFORE the protected-fd reroll so the
	 * reroll still has the last word on fd selection. */
	if (rnd_modulo_u32(100) < 25) {
		int fd = get_rand_writeable_pagecache_fd();
		if (fd >= 0)
			rec->a1 = fd;
	}

	/* Belt-and-suspenders: keep the stderr capture memfd (and other
	 * protected fds) out of rec->a1 so a fuzz-induced ftruncate can't
	 * extend it to multi-GB and turn the next SIGABRT-handler bug-log
	 * drain into a host-swamping write. */
	reroll_protected_fd_arg(&rec->a1);
}

static void post_ftruncate(struct syscallrecord *rec)
{
	if (rec->retval != 0)
		return;

	/*
	 * Truncate-down past a mapped extent destroys the backing pages of
	 * the tail and a subsequent access through any OBJ_MMAP_FILE /
	 * TESTFILE entry against this fd SIGBUSes on the first past-EOF
	 * page.  We do not snapshot the pre-call size to gate on
	 * shrink-vs-grow -- a grow is harmless to invalidate (the next
	 * get_map() pick re-populates the pool), the cost is a few extra
	 * mmap-pool refills, and avoiding the gate keeps the post handler
	 * out of an fstat() syscall on the hot path.  The fd is the one the
	 * kernel was handed, shadowed at dispatch: chain substitution or a
	 * RedQueen pin can rewrite it after the sanitiser drew its own, and
	 * invalidating the mappings of a file the call never cut leaves the
	 * cut one's live.
	 */
	invalidate_obj_mmap_by_fd((int) get_arg_snapshot(rec, 1));
}

struct syscallentry syscall_ftruncate = {
	.name = "ftruncate",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "length" },
	.sanitise = sanitise_ftruncate,
	.post = post_ftruncate,
	/* fd (a1): the mappings invalidated are those of the file the
	 * kernel cut. */
	.arg_snapshot_mask = (1u << 0),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.group = GROUP_VFS_IO,
};


/*
 * SYSCALL_DEFINE(ftruncate64)(unsigned int fd, loff_t length)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */

struct syscallentry syscall_ftruncate64 = {
	.name = "ftruncate64",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "length" },
	.sanitise = sanitise_ftruncate,
	.post = post_ftruncate,
	/* fd (a1): the mappings invalidated are those of the file the
	 * kernel cut. */
	.arg_snapshot_mask = (1u << 0),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.group = GROUP_VFS_IO,
};
