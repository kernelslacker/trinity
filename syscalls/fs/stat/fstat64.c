/*
 * SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <fcntl.h>
#include <sys/stat.h>
#include "arch.h"
#include "output-poison.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"

/*
 * Snapshot of the fstat64 output-buffer pointer + poison seed the
 * post oracle needs, captured at sanitise time.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot retarget the untouched-buffer
 * check at a foreign user allocation.  The poison seed travels with
 * the pointer so a stomp cannot smear the seed against a heap page
 * that happens to still carry a residual pattern from an earlier call.
 */
#define FSTAT64_POST_STATE_MAGIC	0x46535436UL	/* "FST6" */
struct fstat64_post_state {
	unsigned long magic;
	unsigned long statbuf;
	uint64_t poison_seed;
};

static void sanitise_fstat64(struct syscallrecord *rec)
{
	struct fstat64_post_state *snap;
	void *buf;

	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a2, page_size);

	/*
	 * ARG_NON_NULL_ADDRESS draws from get_writable_address(), which
	 * returns NULL when the writable pool cannot satisfy the requested
	 * mapping_sizes[] draw (~7/9 of picks, since mapping_sizes runs up
	 * to GB(1) but the pool is 1 MiB).  Skip the poison + snap install
	 * on those calls -- writing a poison pattern to a NULL user pointer
	 * would SIGSEGV inside the sanitiser and mask the syscall path we
	 * are trying to fuzz.  range_readable_user() also filters raw fuzz
	 * addresses that fell outside the tracked shared / libc-heap
	 * snapshots (the pool is track_shared_region()'d, so pool-vended
	 * addresses always pass); those addresses may not be writable and
	 * the poison stamp would fault the same way.  On skip, rec->post_state
	 * stays 0 -- post_state_claim_owned() returns NULL and the post
	 * handler no-ops without ever touching the pointer.
	 */
	buf = (void *)(unsigned long) rec->a2;
	if (!range_readable_user(buf, sizeof(struct stat64)))
		return;

	/*
	 * Snapshot the output-buffer pointer + poison seed for the post
	 * oracle.  Without this the post handler reads rec->a2 at post-
	 * time, when a sibling syscall may have scribbled the slot:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original user statbuf pointer, so the poison
	 * check would touch a foreign allocation and mistake stale bytes
	 * elsewhere for a real "untouched" signal.  Stamp the poison after
	 * avoid_shared_buffer_out() so it lands on the final buffer the
	 * kernel will see; the returned seed is fed back into
	 * check_output_struct() in the post handler.  post_state is
	 * private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = FSTAT64_POST_STATE_MAGIC;
	snap->statbuf     = rec->a2;
	snap->poison_seed = poison_output_struct(buf, sizeof(struct stat64), 0);
	post_state_install(rec, snap);
}

/*
 * Oracle: fstat64(fd, statbuf) writes the inode metadata of the file
 * named by fd into the user struct stat64.  This post handler catches
 * the "returned success but wrote zero bytes" bug shape by stamping a
 * per-call poison pattern into the output buffer at sanitise time and
 * asking check_output_struct() whether the pattern survived intact on
 * a success return.  A byte-identical poison after a 0-retval means
 * the kernel never called copy_to_user() at all, or copied fewer bytes
 * than sizeof(struct stat64) implies and left an uninitialised-field
 * tail readable in user memory (a kernel->user infoleak).  Snapshot
 * the buffer via post_snapshot_or_skip so a sibling munmap of the
 * writable-pool page between syscall return and the poison compare
 * degrades to a skipped sample instead of a SIGSEGV in
 * check_output_struct's byte-walk; false from the snapshot means the
 * buffer is not provably readable now and the sample is skipped.
 * Counts against the shared post_handler_untouched_out_buf slot -- no
 * per-syscall counter here, so this file stays a one-file change.
 */
static void post_fstat64(struct syscallrecord *rec)
{
	struct fstat64_post_state *snap;
	struct stat64 snapshot;

	snap = post_state_claim_owned(rec, FSTAT64_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	if (!post_snapshot_or_skip(&snapshot,
				   (void *)(unsigned long) snap->statbuf,
				   sizeof(snapshot)))
		goto out_release;

	if (check_output_struct(&snapshot, sizeof(snapshot), snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_fstat64 = {
	.name = "fstat64",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "fd", [1] = "statbuf" },
	.sanitise = sanitise_fstat64,
	.post = post_fstat64,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,
	struct stat64 __user *, statbuf, int, flag)
 *
 * On success, fstatat() returns 0.
 * On error, -1 is returned and errno is set to indicate the error.
 */

/*
 * statx-only sync-type bits.  The kernel bounces any of these on
 * fstatat64 with -EINVAL before touching the output buffer; used by
 * sanitise_fstatat64 to keep the reject path warm without dominating
 * the success mix.  Values are stable uapi (linux/stat.h) -- defined
 * locally to avoid pulling <linux/fcntl.h> against the glibc <fcntl.h>
 * already included above.
 */
#ifndef AT_STATX_FORCE_SYNC
#define AT_STATX_FORCE_SYNC	0x2000
#endif
#ifndef AT_STATX_DONT_SYNC
#define AT_STATX_DONT_SYNC	0x4000
#endif

/*
 * Curated combinations of the three AT_* bits the kernel accepts for
 * fstatat64: AT_SYMLINK_NOFOLLOW (lstat semantics on the final
 * component), AT_NO_AUTOMOUNT (suppress automount triggering), and
 * AT_EMPTY_PATH (empty pathname stats the dfd itself).  0 covers the
 * plain "follow symlinks, default lookup" mode.  Full-mask and pair
 * combos ensure the flag-mask decode path exercises every accepted
 * bit position, not just the singles the original three-entry table
 * covered.  Foreign / statx-only bits are injected by
 * sanitise_fstatat64 below on a fraction of calls rather than baked
 * into this list so the ARG_LIST pick keeps landing on kernel-legal
 * combos most of the time.
 */
static unsigned long fstatat_flags[] = {
	0,
	AT_EMPTY_PATH,
	AT_SYMLINK_NOFOLLOW,
	AT_NO_AUTOMOUNT,
	AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT,
	AT_EMPTY_PATH | AT_NO_AUTOMOUNT,
	AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH,
	AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT,
};

/*
 * Snapshot of the fstatat64 output-buffer pointer + poison seed the
 * post oracle needs, captured at sanitise time.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot retarget the untouched-buffer
 * check.  Only the statbuf and its poison seed are captured -- this
 * oracle asks "did the kernel touch the statbuf on retval=0?", which
 * is a property of the output buffer alone; the input dfd / pathname
 * / flag do not feed the check.
 */
#define FSTATAT64_POST_STATE_MAGIC	0x46534136UL	/* "FSA6" */
struct fstatat64_post_state {
	unsigned long magic;
	unsigned long statbuf;
	uint64_t poison_seed;
};

static void sanitise_fstatat64(struct syscallrecord *rec)
{
	struct fstatat64_post_state *snap;
	void *buf;

	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a3, page_size);

	/*
	 * Occasionally OR in statx-only AT_STATX_* sync-type bits on top
	 * of the ARG_LIST pick.  fstatat64's flag validator rejects any
	 * bit outside {AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT, AT_EMPTY_PATH}
	 * with -EINVAL before touching the output buffer, so this keeps
	 * the reject path exercised without swamping the success-return
	 * mix.  The .post oracle short-circuits on non-zero retval, so
	 * these calls do not fabricate false untouched-buffer reports.
	 */
	if (ONE_IN(8))
		rec->a4 |= AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC;

	/*
	 * See sanitise_fstat64 for why we gate the poison stamp on
	 * range_readable_user(): ARG_NON_NULL_ADDRESS can hand us NULL when
	 * the writable pool cannot back the requested mapping size, and
	 * writing poison into NULL / an unmapped fuzz address would SIGSEGV
	 * the sanitiser.  Skip snap install on the not-provably-writable
	 * path; the post handler no-ops via post_state_claim_owned() ==
	 * NULL.
	 */
	buf = (void *)(unsigned long) rec->a3;
	if (!range_readable_user(buf, sizeof(struct stat64)))
		return;

	/*
	 * Snapshot the output-buffer pointer + poison seed for the post
	 * oracle.  Without this the post handler reads rec->a3 at
	 * post-time, when a sibling syscall may have scribbled the slot:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original user statbuf pointer, so the poison
	 * check would touch a foreign allocation and mistake stale bytes
	 * elsewhere for a real "untouched" signal.  Stamp the poison
	 * after avoid_shared_buffer_out() so it lands on the final buffer
	 * the kernel will see.  post_state is private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = FSTATAT64_POST_STATE_MAGIC;
	snap->statbuf     = rec->a3;
	snap->poison_seed = poison_output_struct(buf, sizeof(struct stat64), 0);
	post_state_install(rec, snap);
}

/*
 * Oracle: fstatat64(dfd, path, statbuf, flag) is the path-based
 * sibling of fstat64.  Same "kernel returned success but wrote
 * nothing" / "kernel wrote a truncated struct" bug shape applies --
 * poison the output buffer at sanitise time and verify the poison
 * did not survive a 0-retval.  See post_fstat64 for the full
 * rationale; this handler mirrors it against the sanitised statbuf
 * pointer in rec->a3.
 */
static void post_fstatat64(struct syscallrecord *rec)
{
	struct fstatat64_post_state *snap;
	struct stat64 snapshot;

	snap = post_state_claim_owned(rec, FSTATAT64_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	if (!post_snapshot_or_skip(&snapshot,
				   (void *)(unsigned long) snap->statbuf,
				   sizeof(snapshot)))
		goto out_release;

	if (check_output_struct(&snapshot, sizeof(snapshot), snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_fstatat64 = {
	.name = "fstatat64",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_NON_NULL_ADDRESS, [3] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "statbuf", [3] = "flag" },
	.arg_params[3].list = ARGLIST(fstatat_flags),
	.sanitise = sanitise_fstatat64,
	.post = post_fstatat64,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.group = GROUP_VFS,
};
