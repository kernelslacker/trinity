/*
 * SYSCALL_DEFINE2(newstat, const char __user *, filename, struct stat __user *, statbuf)
 */
#include <limits.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "arch.h"
#include "output-poison.h"
#include "pathnames.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the two newstat input args plus the poison seed read by
 * the post oracle, captured at sanitise time and consumed by the post
 * handler.  Lives in rec->post_state, a slot the syscall ABI does not
 * expose, so a sibling syscall scribbling rec->aN between the syscall
 * returning and the post handler running cannot steer the source memcpy
 * at a foreign user statbuf or smear the poison seed against a heap
 * page that happens to still carry a residual pattern from an earlier
 * call.  The pathname is snapshotted by VALUE into the embedded byte
 * buffer below rather than by pointer -- a stale heap-shaped filename
 * pointer that survived looks_like_corrupted_ptr's shape-only gate would
 * otherwise let the .post strncpy walk off the end of an unrelated
 * allocation, and a sibling rewrite of the bytes between sanitise and
 * post would forge a clean-looking divergence.  A poison_seed of 0
 * means the sanitise-time writability check refused to stamp poison
 * for this call and the post handler must no-op the untouched-buffer
 * check.
 */
#define NEWSTAT_POST_STATE_MAGIC	0x4E534154UL	/* "NSAT" */
struct newstat_post_state {
	unsigned long magic;
	unsigned long statbuf;
	uint64_t poison_seed;
	char filename[PATH_MAX];
};

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so the pin lands
 * on an existing trinity-owned inode and concentrates cross-process
 * contention on the same per-inode i_rwsem / getattr path the other
 * path-pinned sanitisers already target.
 */
#define NR_TESTFILES 4

static void sanitise_newstat(struct syscallrecord *rec)
{
	struct newstat_post_state *snap;
	char *path;

	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a2, page_size);

	/*
	 * Snapshot input state for the post oracle.  Without this the
	 * post handler reads rec->aN at post-time, when a sibling syscall
	 * may have scribbled the slots: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original user
	 * statbuf pointer, so the source memcpy would touch a foreign
	 * allocation, and a stale rec->a1 / sibling-rewritten pathname
	 * bytes would let the re-issue resolve a different file (or a
	 * different symlink target) entirely.  Snapshot the filename BYTES
	 * via post_snapshot_str so the post handler never re-derefs the
	 * user pointer; skip the post sample entirely when the snapshot
	 * source is not provably readable.  post_state is private to the
	 * post handler.  post_state_install pairs the rec->post_state
	 * assign with the ownership-table register so the observable
	 * window between the two is closed; post_newstat() will then
	 * gate the snap through post_state_claim_owned() and prove
	 * ownership before dereferencing any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic    = NEWSTAT_POST_STATE_MAGIC;
	snap->statbuf  = rec->a2;
	if (!post_snapshot_str(snap->filename, sizeof(snap->filename),
			       (const char *)(unsigned long) rec->a1))
		snap->filename[0] = '\0';
	/*
	 * Stamp a per-call poison pattern into the user struct stat the
	 * kernel is about to fill.  The post handler feeds the seed back
	 * into check_output_struct(); a byte-identical poison after a
	 * retval == 0 return means the kernel skipped copy_to_user()
	 * entirely -- newstat(2) contracts to overwrite the whole
	 * struct stat on success via cp_new_stat().  Gate on
	 * range_readable_user() so a writable-pool draw that
	 * avoid_shared_buffer_out() moved to an address that is no
	 * longer provably mapped -- e.g. a sibling munmap between
	 * allocation and now -- does not SIGSEGV the sanitiser inside
	 * poison_output_struct's byte-walk.  On skip, poison_seed stays
	 * 0 and the post handler no-ops the poison check while the
	 * field-diff oracle still runs against snap->statbuf.  Done
	 * after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see.
	 */
	{
		void *buf = (void *)(unsigned long) rec->a2;

		if (range_readable_user(buf, sizeof(struct stat)))
			snap->poison_seed = poison_output_struct(buf,
								 sizeof(struct stat),
								 0);
	}
	post_state_install(rec, snap);

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real file -- newstat ENOENT-
	 * walls at the namei walk before reaching the per-fs
	 * inode_operations->getattr path under i_rwsem.  Half the draws
	 * now repoint rec->a1 at one of the trinity-testfile<N> absolute
	 * paths so the call lands on a real trinity-owned inode and
	 * penetrates the VFS path; the other half preserves the slot
	 * exactly as the generic draw left it so the ENOENT reject arm
	 * stays exercised.  generate_pathname() zmallocs MAX_PATH_LEN
	 * (4096) bytes for the ARG_PATHNAME buffer, so the snprintf cap
	 * below cannot overflow.  Pin runs after post_state_install so
	 * the snapshot the oracle re-issues against is the pre-pin
	 * filename; on pinned draws the re-call ENOENTs on the random
	 * snapshot and the oracle safely bails -- the oracle/post path
	 * is left additive and untouched.
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	path = get_testfile_path();
	if (path == NULL)
		return;

	rec->a1 = (unsigned long) path;
}

/*
 * Oracle: newstat(filename, statbuf) is the symlink-following variant of
 * newlstat — stat() resolves the path through any intermediate symlinks
 * and writes the inode metadata of the *target* into the user struct stat.
 * For the resolved target, every inode-attribute field is byte-stable
 * across the ~150ms window between the original syscall return and our
 * post-hook re-call: st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid,
 * st_rdev, st_size, st_blksize, st_blocks all live on the inode and only
 * change via chmod / chown / link / truncate / unlink-and-replace on the
 * resolved target.  st_atim/st_mtim/st_ctim are excluded from the compare:
 * because stat() follows the symlink, atim on the resolved target can
 * legitimately advance if a sibling reads through the same path between
 * our two calls (read updates atim), and mtim/ctim can advance under a
 * sibling chmod/chown/write.  Excluding the three timestamps keeps the
 * false-positive rate near zero.  A divergence in the remaining ten
 * fields is not benign drift; it points at one of:
 *
 *   - copy_to_user mis-write that leaves a torn struct stat in user
 *     memory (partial write, wrong-offset fill, residual stack data).
 *   - 32-bit-on-64-bit compat sign-extension of st_size, st_dev, or
 *     st_rdev (e.g. a small positive size sign-extending to 0xFFFF...).
 *   - struct-layout mismatch shifting st_dev into the st_ino slot, or
 *     st_blocks into st_blksize, on a kernel/glibc skew.
 *   - sibling-thread scribble of the user receive buffer between syscall
 *     return and our post-hook re-read.
 *
 * TOCTOU defeat (two buffers worth of it): both the input pathname and
 * the output stat buffer are user memory and a sibling can scribble
 * either between original return and re-issue.  The pathname is the
 * dominant attack surface — alloc_shared can hand it to another child
 * which then scribbles it; if we re-call with whatever rec->a1 holds
 * by then we may resolve a different file (or a different symlink target),
 * get different inode metadata, and report a false divergence.  Snapshot
 * BOTH the path (PATH_MAX stack buffer) and the original stat result
 * before the re-call.  If the re-call fails, give up rather than report.
 * Compare each field individually with no early-return so multi-field
 * corruption surfaces in a single sample, but bump the anomaly counter
 * only once per sample.  Sample one in a hundred to stay in line with
 * the rest of the oracle family and complement the newlstat oracle.
 */
static void post_newstat(struct syscallrecord *rec)
{
	struct newstat_post_state *snap;
	struct stat first, recheck;
	int diverged = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, NEWSTAT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	if (snap->statbuf == 0)
		goto out_release;

	/*
	 * Untouched-buffer check: newstat returned 0 (success) but the
	 * user struct stat still byte-for-byte matches the poison
	 * pattern we stamped at sanitise time -- the kernel never called
	 * copy_to_user() at all.  Runs on every success (no ONE_IN gate)
	 * because the check is a ~sizeof(struct stat) memcmp with no
	 * re-issue, so it stays cheap enough to fire every time; bumps
	 * the shared post_handler_untouched_out_buf slot.  Skip when
	 * poison_seed is 0: sanitise refused to stamp (unmapped
	 * statbuf) so there is no pattern to compare against.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->statbuf,
					     sizeof(struct stat),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_release;

	if (snap->filename[0] == '\0')
		goto out_release;

	if (!post_snapshot_or_skip(&first,
				   (void *)(unsigned long) snap->statbuf,
				   sizeof(first)))
		goto out_release;

	if (syscall(SYS_newfstatat, AT_FDCWD, snap->filename, &recheck, 0) != 0)
		goto out_release;

	if (first.st_dev     != recheck.st_dev)     diverged = 1;
	if (first.st_ino     != recheck.st_ino)     diverged = 1;
	if (first.st_mode    != recheck.st_mode)    diverged = 1;
	if (first.st_nlink   != recheck.st_nlink)   diverged = 1;
	if (first.st_uid     != recheck.st_uid)     diverged = 1;
	if (first.st_gid     != recheck.st_gid)     diverged = 1;
	if (first.st_rdev    != recheck.st_rdev)    diverged = 1;
	if (first.st_size    != recheck.st_size)    diverged = 1;
	if (first.st_blksize != recheck.st_blksize) diverged = 1;
	if (first.st_blocks  != recheck.st_blocks)  diverged = 1;

	if (!diverged)
		goto out_release;

	output(0,
	       "newstat oracle anomaly: path=%s "
	       "first={dev=%lx,ino=%lu,mode=%o,nlink=%lu,uid=%u,gid=%u,"
	       "rdev=%lx,size=%lld,blksize=%ld,blocks=%lld} "
	       "recall={dev=%lx,ino=%lu,mode=%o,nlink=%lu,uid=%u,gid=%u,"
	       "rdev=%lx,size=%lld,blksize=%ld,blocks=%lld}\n",
	       snap->filename,
	       (unsigned long) first.st_dev, (unsigned long) first.st_ino,
	       (unsigned int) first.st_mode, (unsigned long) first.st_nlink,
	       (unsigned int) first.st_uid, (unsigned int) first.st_gid,
	       (unsigned long) first.st_rdev, (long long) first.st_size,
	       (long) first.st_blksize, (long long) first.st_blocks,
	       (unsigned long) recheck.st_dev, (unsigned long) recheck.st_ino,
	       (unsigned int) recheck.st_mode, (unsigned long) recheck.st_nlink,
	       (unsigned int) recheck.st_uid, (unsigned int) recheck.st_gid,
	       (unsigned long) recheck.st_rdev, (long long) recheck.st_size,
	       (long) recheck.st_blksize, (long long) recheck.st_blocks);

	__atomic_add_fetch(&shm->stats.oracle.newstat_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_newstat = {
	.name = "newstat",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_newstat,
	.post = post_newstat,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
