/*
 * SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *, buf)
 */
#include <limits.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <stdio.h>
#include "arch.h"
#include "output-poison.h"
#include "pathnames.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers (chmod, utime, xattr-thrash, flock-thrash, ...) touch;
 * cross-process contention concentrates on the same per-inode i_rwsem /
 * statfs path.
 */
#define NR_TESTFILES 4

#if defined(SYS_statfs) || defined(__NR_statfs)
/*
 * Snapshot of the two statfs input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives
 * in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot steer the source memcpy at a
 * foreign user buffer.  The pathname is snapshotted by VALUE into the
 * embedded byte buffer below rather than by pointer -- a stale heap-
 * shaped pathname pointer that survived looks_like_corrupted_ptr's
 * shape-only gate would otherwise let the .post strncpy walk off the
 * end of an unrelated allocation, and a sibling rewrite of the bytes
 * between sanitise and post would forge a clean-looking divergence.
 */
#define STATFS_POST_STATE_MAGIC	0x53544653UL	/* "STFS" */
struct statfs_post_state {
	unsigned long magic;
	unsigned long buf;
	uint64_t poison_seed;
	char pathname[PATH_MAX];
};
#endif

static void sanitise_statfs(struct syscallrecord *rec)
{
	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real file at all -- statfs
	 * returns ENOENT at the path walk before ever reaching the
	 * per-fs ->statfs super_op and the mount-level statistics
	 * gather.  Classic "high calls, low edges" cold-syscall shape
	 * the chmod / utime / xattr families were in before their
	 * testfile-pin fixes.
	 *
	 * Half the draws now repoint at one of the trinity-testfile<N>
	 * absolute paths so the subsequent statfs lands on a real
	 * trinity-owned inode and penetrates the path walk and the
	 * per-fs ->statfs super_op.  The other half preserves the slot
	 * exactly as the generic draw left it, so the ENOENT reject
	 * arm stays exercised.
	 *
	 * Done as an if-block rather than an early-return so the
	 * existing avoid_shared_buffer_out() on a2 and the post_state
	 * snapshot below still run on both halves -- the path pin is
	 * purely additive to the existing a2 / post-oracle work.
	 */
	if (rnd_modulo_u32(2) == 0) {
		char *path = get_testfile_path();

		if (path != NULL)
			rec->a1 = (unsigned long) path;
	}

	avoid_shared_buffer_out(&rec->a2, page_size);

#if defined(SYS_statfs) || defined(__NR_statfs)
	{
		struct statfs_post_state *snap;

		rec->post_state = 0;

		/*
		 * Snapshot input state for the post oracle.  Without this
		 * the post handler reads rec->aN at post-time, when a
		 * sibling syscall may have scribbled the slots:
		 * looks_like_corrupted_ptr() cannot tell a real-but-wrong
		 * heap address from the original user buf pointer, so the
		 * source memcpy would touch a foreign allocation, and a
		 * stale rec->a1 / sibling-rewritten pathname bytes would
		 * let the re-issue resolve a different mount entirely.
		 * Snapshot the pathname BYTES via post_snapshot_str so the
		 * post handler never re-derefs the user pointer; skip the
		 * post sample when the snapshot source is not provably
		 * readable.  post_state is private to the post handler.
		 * post_state_install pairs the rec->post_state assign with
		 * the ownership-table register so the observable window
		 * between the two is closed; post_statfs() will then gate
		 * the snap through post_state_claim_owned() and prove
		 * ownership before dereferencing any field.
		 */
		snap = zmalloc_tracked(sizeof(*snap));
		snap->magic    = STATFS_POST_STATE_MAGIC;
		snap->buf      = rec->a2;
		if (!post_snapshot_str(snap->pathname, sizeof(snap->pathname),
				       (const char *)(unsigned long) rec->a1))
			snap->pathname[0] = '\0';

		/*
		 * Stamp a per-call poison pattern across the OUT struct the
		 * kernel is about to fill.  On success the post handler asks
		 * check_output_struct() whether every byte still matches --
		 * an intact pattern means the kernel returned 0 without any
		 * copy_to_user() of the writeback (short or absent copy leaks
		 * whatever was in the user page before).  Gate on
		 * range_readable_user() so a NULL/short user pointer from the
		 * ARG_NON_NULL_ADDRESS pool cannot SIGSEGV inside the byte-
		 * walk; on skip the seed stays zero and the post check no-ops.
		 * Done after avoid_shared_buffer_out() so the poison lands on
		 * the final buffer the kernel will see.
		 */
		if (rec->a2 != 0 &&
		    range_readable_user((void *)(unsigned long) rec->a2,
					sizeof(struct statfs)))
			snap->poison_seed = poison_output_struct(
				(void *)(unsigned long) rec->a2,
				sizeof(struct statfs), 0);

		post_state_install(rec, snap);
	}
#endif
}

/*
 * Oracle: statfs(pathname, buf) is the path-based sibling of fstatfs.
 * The kernel resolves pathname to a dentry, walks to its mount, and
 * fills struct statfs with the same eight stable fields plus the three
 * legitimately-drifting free-space counters.  The same divergence
 * sources apply (copy_to_user mis-write, struct-layout shift, compat
 * truncation, sibling scribble of the user buffer, genuine remount or
 * online-resize), so the oracle compares the same eight fields and
 * excludes f_bfree, f_bavail, f_ffree, plus the reserved f_spare[].
 *
 * Two differences from the fd-based variant change the shape of the
 * recheck:
 *
 *   - Path TOCTOU.  Between the original syscall return and the
 *     recheck a sibling can rename, unlink, or replace the directory
 *     entry that pathname referred to.  rec->a1 still points at the
 *     caller's original buffer, so re-reading from rec->a1 at recheck
 *     time would walk a path string that may have been overwritten
 *     after the original return.  Snapshot pathname into a stack
 *     buffer (PATH_MAX) before the re-issue so the recheck mirrors the
 *     exact bytes the kernel resolved the first time.
 *
 *   - Mount drift.  Even with a stable path string a sibling can
 *     unmount and remount a different filesystem at the same mount
 *     point between the two calls; the recheck then describes a
 *     completely different mount and every stable field will look
 *     "wrong".  f_fsid is the kernel's per-mount identifier — if
 *     snapshot.f_fsid != recheck.f_fsid we know we are looking at a
 *     different mount and benign-skip the sample without bumping the
 *     anomaly counter.  Both halves of f_fsid must match.
 *
 * The benign-skip paths are: rc != 0 from the recheck (path no longer
 * resolvable: sibling unlink/rename/unmount made it disappear) and
 * f_fsid mismatch (mount drift).  Sample one in a hundred to stay in
 * line with the rest of the oracle family.  Compare each field
 * individually with no early-return so multi-field corruption surfaces
 * in a single sample, but bump the anomaly counter only once per
 * anomalous sample.
 *
 * Some 32-bit-only architectures fold statfs into statfs64 and do not
 * define SYS_statfs.  Guard the .post handler and wire-up so the file
 * still compiles cleanly in those configurations; the syscall table on
 * those builds never reaches syscall_statfs anyway, so the .post hook
 * is unreachable in practice.
 */
#if defined(SYS_statfs) || defined(__NR_statfs)
static void post_statfs(struct syscallrecord *rec)
{
	struct statfs_post_state *snap;
	struct statfs first, recheck;
	int diverged = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, STATFS_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	if (snap->buf == 0)
		goto out_release;

	/*
	 * Output-struct poison check: runs on every success (cheap memcmp
	 * against a stack pattern, no re-issue).  An intact poison after
	 * retval==0 means the kernel skipped copy_to_user() entirely, or
	 * short-copied and left an uninitialised tail readable in user
	 * memory -- a kernel->user infoleak.  Counts against the shared
	 * post_handler_untouched_out_buf slot alongside the other
	 * untouched-buffer signals.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->buf,
					     sizeof(struct statfs),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (snap->pathname[0] == '\0')
		goto out_release;

	if (!ONE_IN(100))
		goto out_release;

	if (!post_snapshot_or_skip(&first,
				   (void *)(unsigned long) snap->buf,
				   sizeof(first)))
		goto out_release;

	if (syscall(SYS_statfs, snap->pathname, &recheck) != 0)
		goto out_release;

	if (first.f_fsid.__val[0] != recheck.f_fsid.__val[0] ||
	    first.f_fsid.__val[1] != recheck.f_fsid.__val[1])
		goto out_release;

	if (first.f_type    != recheck.f_type)    diverged = 1;
	if (first.f_bsize   != recheck.f_bsize)   diverged = 1;
	if (first.f_blocks  != recheck.f_blocks)  diverged = 1;
	if (first.f_files   != recheck.f_files)   diverged = 1;
	if (first.f_namelen != recheck.f_namelen) diverged = 1;
	if (first.f_frsize  != recheck.f_frsize)  diverged = 1;
	if (first.f_flags   != recheck.f_flags)   diverged = 1;

	if (!diverged)
		goto out_release;

	output(0,
	       "statfs oracle anomaly: path=%s "
	       "first={type=%lx,bsize=%ld,blocks=%llu,files=%llu,"
	       "namelen=%ld,frsize=%ld,flags=%lx,fsid=%x:%x} "
	       "recall={type=%lx,bsize=%ld,blocks=%llu,files=%llu,"
	       "namelen=%ld,frsize=%ld,flags=%lx,fsid=%x:%x}\n",
	       snap->pathname,
	       (unsigned long) first.f_type, (long) first.f_bsize,
	       (unsigned long long) first.f_blocks,
	       (unsigned long long) first.f_files,
	       (long) first.f_namelen, (long) first.f_frsize,
	       (unsigned long) first.f_flags,
	       (unsigned int) first.f_fsid.__val[0],
	       (unsigned int) first.f_fsid.__val[1],
	       (unsigned long) recheck.f_type, (long) recheck.f_bsize,
	       (unsigned long long) recheck.f_blocks,
	       (unsigned long long) recheck.f_files,
	       (long) recheck.f_namelen, (long) recheck.f_frsize,
	       (unsigned long) recheck.f_flags,
	       (unsigned int) recheck.f_fsid.__val[0],
	       (unsigned int) recheck.f_fsid.__val[1]);

	__atomic_add_fetch(&shm->stats.oracle.statfs_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}
#endif

struct syscallentry syscall_statfs = {
	.name = "statfs",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pathname", [1] = "buf" },
	.sanitise = sanitise_statfs,
#if defined(SYS_statfs) || defined(__NR_statfs)
	.post = post_statfs,
#endif
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};

/*
 * SYSCALL_DEFINE3(statfs64, const char __user *, pathname, size_t, sz, struct statfs64 __user *, buf)
 */

#ifdef SYS_statfs64
/*
 * Snapshot of the three statfs64 input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives
 * in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot smear the buffer-size word used
 * to seed the re-issue or steer the source memcpy at a foreign user
 * buffer.  The pathname is snapshotted by VALUE into the embedded byte
 * buffer below rather than by pointer -- a stale heap-shaped pathname
 * pointer that survived looks_like_corrupted_ptr's shape-only gate
 * would otherwise let the .post strncpy walk off the end of an
 * unrelated allocation, and a sibling rewrite of the bytes between
 * sanitise and post would forge a clean-looking divergence.
 */
#define STATFS64_POST_STATE_MAGIC	0x53544636UL	/* "STF6" */
struct statfs64_post_state {
	unsigned long magic;
	unsigned long sz;
	unsigned long buf;
	uint64_t poison_seed;
	char pathname[PATH_MAX];
};
#endif

static void sanitise_statfs64(struct syscallrecord *rec)
{
	/*
	 * Same testfile pin as sanitise_statfs: ARG_PATHNAME at rec->a1
	 * is otherwise a random pathname that ENOENT-walls before the
	 * per-fs ->statfs super_op.  Pin to a trinity-testfile<N>
	 * absolute path half the time so half the draws penetrate a
	 * real inode and half preserve the ENOENT arm.  Placed as an
	 * if-block (not an early return) so the existing a3 buffer
	 * sanitise and the post_state snapshot below still run on both
	 * halves.
	 */
	if (rnd_modulo_u32(2) == 0) {
		char *path = get_testfile_path();

		if (path != NULL)
			rec->a1 = (unsigned long) path;
	}

	avoid_shared_buffer_out(&rec->a3, rec->a2 ? rec->a2 : page_size);

#ifdef SYS_statfs64
	{
		struct statfs64_post_state *snap;

		rec->post_state = 0;

		/*
		 * Snapshot input state for the post oracle.  Without this
		 * the post handler reads rec->aN at post-time, when a
		 * sibling syscall may have scribbled the slots:
		 * looks_like_corrupted_ptr() cannot tell a real-but-wrong
		 * heap address from the original user buf pointer, so the
		 * source memcpy would touch a foreign allocation, a stomped
		 * sz word would change the buffer-size semantics on the
		 * re-issue, and a stale rec->a1 / sibling-rewritten pathname
		 * bytes would let the re-issue resolve a different mount.
		 * Snapshot the pathname BYTES via post_snapshot_str so the
		 * post handler never re-derefs the user pointer; skip the
		 * post sample when the snapshot source is not provably
		 * readable.  post_state is private to the post handler.
		 * post_state_install pairs the rec->post_state assign with
		 * the ownership-table register so the observable window
		 * between the two is closed; post_statfs64() will then gate
		 * the snap through post_state_claim_owned() and prove
		 * ownership before dereferencing any field.
		 */
		snap = zmalloc_tracked(sizeof(*snap));
		snap->magic    = STATFS64_POST_STATE_MAGIC;
		snap->sz       = rec->a2;
		snap->buf      = rec->a3;
		if (!post_snapshot_str(snap->pathname, sizeof(snap->pathname),
				       (const char *)(unsigned long) rec->a1))
			snap->pathname[0] = '\0';

		/*
		 * Stamp a per-call poison across the OUT struct so the post
		 * handler can detect a success-with-no-copy_to_user leak.
		 * statfs64 requires sz == sizeof(struct statfs64) or the
		 * kernel rejects with -EINVAL before touching the buffer, so
		 * on the retval==0 path the kernel will overwrite exactly
		 * sizeof(struct statfs64) bytes.  Gate on
		 * range_readable_user() so a NULL or short buffer from the
		 * ARG_NON_NULL_ADDRESS pool cannot SIGSEGV inside the byte
		 * walk; on skip the seed stays zero and the post check
		 * no-ops.  Poison after avoid_shared_buffer_out() so it
		 * lands on the final buffer the kernel will see.
		 */
		if (rec->a3 != 0 &&
		    range_readable_user((void *)(unsigned long) rec->a3,
					sizeof(struct statfs64)))
			snap->poison_seed = poison_output_struct(
				(void *)(unsigned long) rec->a3,
				sizeof(struct statfs64), 0);

		post_state_install(rec, snap);
	}
#endif
}

/*
 * Oracle: statfs64(pathname, sz, buf) is the 3-arg explicit-size variant
 * of statfs.  The kernel resolves pathname to a dentry, walks to its
 * mount, and fills struct statfs64 with the same eight stable fields
 * plus the three legitimately-drifting free-space counters.  The post
 * handler mirrors post_statfs exactly: TOCTOU pathname snapshot into a
 * PATH_MAX stack buffer before the recheck, f_fsid mount-drift gate
 * (both halves must match), and field-by-field comparison of the eight
 * stable fields with no early return so multi-field corruption surfaces
 * in a single sample.  The only shape delta from post_statfs is the sz
 * argument: snapshot rec->a2 and pass that exact value back into the
 * recheck issue rather than synthesizing one, so the recheck sees the
 * same buffer-size semantics the kernel saw the first time.
 *
 * Some 64-bit architectures fold statfs64 into statfs and do not define
 * SYS_statfs64.  Guard the .post handler and wire-up so the file still
 * compiles cleanly in those configurations; the syscall table on those
 * builds never reaches syscall_statfs64 anyway, so the .post hook is
 * unreachable in practice.
 */
#ifdef SYS_statfs64
static void post_statfs64(struct syscallrecord *rec)
{
	struct statfs64_post_state *snap;
	struct statfs64 first, recheck;
	size_t sz_snapshot;
	int diverged = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, STATFS64_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	if (snap->sz < sizeof(struct statfs64))
		goto out_release;

	if (snap->buf == 0)
		goto out_release;

	/*
	 * Output-struct poison check: runs on every success (cheap memcmp,
	 * no re-issue).  Intact poison after retval==0 means the kernel
	 * skipped copy_to_user() entirely, or short-copied and left an
	 * uninitialised tail readable in user memory (kernel->user
	 * infoleak).  Counts against the shared
	 * post_handler_untouched_out_buf slot.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->buf,
					     sizeof(struct statfs64),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (snap->pathname[0] == '\0')
		goto out_release;

	if (!ONE_IN(100))
		goto out_release;

	sz_snapshot = (size_t) snap->sz;

	if (!post_snapshot_or_skip(&first,
				   (void *)(unsigned long) snap->buf,
				   sizeof(first)))
		goto out_release;

	if (syscall(SYS_statfs64, snap->pathname, sz_snapshot, &recheck) != 0)
		goto out_release;

	if (first.f_fsid.__val[0] != recheck.f_fsid.__val[0] ||
	    first.f_fsid.__val[1] != recheck.f_fsid.__val[1])
		goto out_release;

	if (first.f_type    != recheck.f_type)    diverged = 1;
	if (first.f_bsize   != recheck.f_bsize)   diverged = 1;
	if (first.f_blocks  != recheck.f_blocks)  diverged = 1;
	if (first.f_files   != recheck.f_files)   diverged = 1;
	if (first.f_namelen != recheck.f_namelen) diverged = 1;
	if (first.f_frsize  != recheck.f_frsize)  diverged = 1;
	if (first.f_flags   != recheck.f_flags)   diverged = 1;

	if (!diverged)
		goto out_release;

	output(0,
	       "statfs64 oracle anomaly: path=%s sz=%zu "
	       "first={type=%lx,bsize=%ld,blocks=%llu,files=%llu,"
	       "namelen=%ld,frsize=%ld,flags=%lx,fsid=%x:%x} "
	       "recall={type=%lx,bsize=%ld,blocks=%llu,files=%llu,"
	       "namelen=%ld,frsize=%ld,flags=%lx,fsid=%x:%x}\n",
	       snap->pathname, sz_snapshot,
	       (unsigned long) first.f_type, (long) first.f_bsize,
	       (unsigned long long) first.f_blocks,
	       (unsigned long long) first.f_files,
	       (long) first.f_namelen, (long) first.f_frsize,
	       (unsigned long) first.f_flags,
	       (unsigned int) first.f_fsid.__val[0],
	       (unsigned int) first.f_fsid.__val[1],
	       (unsigned long) recheck.f_type, (long) recheck.f_bsize,
	       (unsigned long long) recheck.f_blocks,
	       (unsigned long long) recheck.f_files,
	       (long) recheck.f_namelen, (long) recheck.f_frsize,
	       (unsigned long) recheck.f_flags,
	       (unsigned int) recheck.f_fsid.__val[0],
	       (unsigned int) recheck.f_fsid.__val[1]);

	__atomic_add_fetch(&shm->stats.oracle.statfs64_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}
#endif

struct syscallentry syscall_statfs64 = {
	.name = "statfs64",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_LEN, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pathname", [1] = "sz", [2] = "buf" },
	.sanitise = sanitise_statfs64,
#ifdef SYS_statfs64
	.post = post_statfs64,
#endif
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
