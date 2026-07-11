/*
 * SYSCALL_DEFINE2(lstat, const char __user *, filename,
		   struct __old_kernel_stat __user *, statbuf)
 */
#include <stdio.h>
#include "arch.h"
#include "output-poison.h"
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers (chmod, utime, stat, ...) touch; cross-process contention
 * concentrates on the same per-inode i_rwsem / getattr path.
 */
#define NR_TESTFILES 4

/*
 * On-success write footprint of the two syscalls below is either
 * struct __old_kernel_stat (~32 bytes, packed 7 shorts + 4 ints/longs)
 * or struct stat64 (well over a hundred bytes).  Poison a conservative
 * prefix both variants are guaranteed to fully overwrite, so a "returned
 * 0 but wrote nothing" bug fires check_output_struct on either variant
 * without false-positives from an unwritten padding tail.
 */
#define LSTAT_POISON_SZ	24

/*
 * Snapshot of the a2 statbuf pointer plus the poison seed read by the
 * post oracle, captured at sanitise time and consumed by the post
 * handler.  Lives in rec->post_state, a slot the syscall ABI does not
 * expose, so a sibling syscall scribbling rec->aN between the syscall
 * returning and the post handler running cannot redirect the poison
 * check against an unrelated heap page that happens to still carry the
 * original (or any) byte pattern.
 */
#define LSTAT_POST_STATE_MAGIC	0x4C535441UL	/* "LSTA" */
struct lstat_post_state {
	unsigned long magic;
	unsigned long statbuf;
	uint64_t poison_seed;
};

static void sanitise_lstat_buf(struct syscallrecord *rec)
{
	struct lstat_post_state *snap;
	char *path;

	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a2, page_size);

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real file at all -- lstat
	 * returns ENOENT at the path walk before ever reaching the
	 * per-fs inode_operations->getattr path under i_rwsem.  Same
	 * "high calls, low edges" cold-syscall shape stat was in before
	 * its testfile-pin fix.
	 *
	 * Half the draws now repoint at one of the trinity-testfile<N>
	 * absolute paths so the subsequent lstat lands on a real
	 * trinity-owned inode and penetrates the VFS path -- the namei
	 * walk to a real dentry, the permission check (trinity owns
	 * these inodes so the ownership/permission gates pass), and the
	 * per-fs getattr that the i_rwsem guards.  The other half
	 * preserves the slot exactly as the generic draw left it, so the
	 * ENOENT reject arm stays exercised.
	 *
	 * Pin lives in the shared sanitiser so both syscall_lstat and
	 * syscall_lstat64 inherit the same behaviour.
	 */
	if (rnd_modulo_u32(2) == 0) {
		path = get_testfile_path();
		if (path != NULL)
			rec->a1 = (unsigned long) path;
	}

	/*
	 * Skip the poison stamp / snap install when rec->a2 is 0: the
	 * ARG_NON_NULL_ADDRESS generator hands back NULL when the
	 * writable-pool draw picks a size larger than the pool (see the
	 * epoll alloc_fail bucket in stats.h for the same shape).  The
	 * syscall will -EFAULT and never reach copy_to_user, so there is
	 * no output to verify; skipping snap install also avoids a
	 * userspace SIGSEGV inside poison_output_struct when writing to
	 * a NULL statbuf.
	 */
	if (rec->a2 == 0)
		return;

	/*
	 * Stamp a per-call poison prefix into the user buffer the kernel
	 * is about to fill.  The post handler asks check_output_struct()
	 * whether the prefix survived intact; if it did on a success
	 * return, the kernel wrote zero bytes despite reporting success.
	 * Done after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see (the relocation may have
	 * swapped rec->a2 for a fresh page).
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = LSTAT_POST_STATE_MAGIC;
	snap->statbuf = rec->a2;
	snap->poison_seed = poison_output_struct((void *)(unsigned long) rec->a2,
						 LSTAT_POISON_SZ, 0);
	post_state_install(rec, snap);
}

/*
 * Oracle: lstat / lstat64 returning 0 must have called copy_to_user()
 * on the caller's statbuf.  Check the poison prefix stamped at sanitise
 * time; if every byte still matches the seeded pattern on a success
 * return the kernel never wrote anything at all -- a torn copy_to_user,
 * a "return 0 before fill" early-exit, or a mis-wired compat wrapper.
 * O(LSTAT_POISON_SZ) memcmp against a stack pattern; no re-issue, so
 * runs on every success rather than the ONE_IN(100) sample used by the
 * heavier field-divergence oracles.  Bumps the shared
 * post_handler_untouched_out_buf counter and lets the anomaly show up
 * in stats/dump.c alongside the other untouched-buffer signals.
 */
static void post_lstat(struct syscallrecord *rec)
{
	struct lstat_post_state *snap;

	snap = post_state_claim_owned(rec, LSTAT_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval == 0 && snap->statbuf != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->statbuf,
					     LSTAT_POISON_SZ, snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	post_state_release(rec, snap);
}

struct syscallentry syscall_lstat = {
	.name = "lstat",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_lstat_buf,
	.post = post_lstat,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};


/*
 * SYSCALL_DEFINE2(lstat64, const char __user *, filename,
		 struct stat64 __user *, statbuf)
 */

struct syscallentry syscall_lstat64 = {
	.name = "lstat64",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_lstat_buf,
	.post = post_lstat,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
