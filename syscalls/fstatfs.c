/*
 * SYSCALL_DEFINE2(fstatfs, unsigned int, fd, struct statfs __user *, buf)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <string.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the two fstatfs input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives
 * in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot retarget the re-issue at a
 * different fd or redirect the source memcpy at a foreign user buffer.
 */
struct fstatfs_post_state {
	unsigned long fd;
	unsigned long buf;
};

static void sanitise_fstatfs(struct syscallrecord *rec)
{
	struct fstatfs_post_state *snap;

	rec->post_state = 0;

	avoid_shared_buffer(&rec->a2, page_size);

	/*
	 * Snapshot the two input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * buf pointer, so the source memcpy would touch a foreign
	 * allocation, and a stomped fd would silently steer the re-issue
	 * against a different mount entirely.  post_state is private to
	 * the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->fd  = rec->a1;
	snap->buf = rec->a2;
	rec->post_state = (unsigned long) snap;
}

/*
 * Oracle: fstatfs(fd, buf) writes filesystem-wide statistics for the
 * mount that backs the open file referenced by fd.  This is the
 * simplest entry of the statfs-family oracle — the descriptor itself
 * names the mount, so there is no path string to snapshot and no
 * name-resolution TOCTOU window for a sibling to widen by scribbling
 * user memory between original return and re-call.
 *
 * Most struct statfs fields describe properties that are intrinsic to
 * the mount and do not drift on benign sibling activity:
 *
 *   - f_type    filesystem magic; pinned for an open inode's mount
 *   - f_bsize   preferred block size; stable for the mount lifetime
 *   - f_blocks  total data blocks; resizing a live FS is rare enough
 *                 that a divergence is worth surfacing
 *   - f_files   total inode slots; same rationale as f_blocks
 *   - f_namelen max filename length; stable per FS type
 *   - f_frsize  fragment size; stable per FS type
 *   - f_flags   mount flags; remount can move them but the event is
 *                 rare enough that we want to know it happened
 *   - f_fsid    filesystem identifier (two ints); pinned per mount
 *
 * The free-space counters (f_bfree, f_bavail, f_ffree) are excluded
 * — every concurrent write, allocate, or unlink legitimately moves
 * them and including them would dwarf any real signal in benign
 * drift.  f_spare[] is also excluded; the kernel zeroes it but the
 * field is reserved padding with no defined stable contract.  A
 * divergence in the remaining eight fields points at one of:
 *
 *   - copy_to_user mis-write that leaves a torn struct statfs in
 *     user memory (partial write, wrong-offset fill, residual stack
 *     data).
 *   - struct-layout shift on a kernel/glibc skew that lands f_type in
 *     the f_bsize slot, or f_blocks in f_files.
 *   - 32-bit-on-64-bit compat sign-extension or truncation of the
 *     wide block / inode counters.
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - genuine remount / online-resize racing the fuzz run, in which
 *     case the divergence is real and worth a log line.
 *
 * The only benign-divergence path is a sibling closing the fd between
 * the original syscall and the recheck — that just makes the recheck
 * fail with -EBADF.  Treat any non-zero return from
 * syscall(SYS_fstatfs) as "give up, sample skipped" so we never
 * report on a torn-down fd.  Sample one in a hundred to stay in line
 * with the rest of the oracle family; compare each field individually
 * with no early-return so multi-field corruption surfaces in a single
 * sample, but bump the anomaly counter only once per sample.
 */
static void post_fstatfs(struct syscallrecord *rec)
{
	struct fstatfs_post_state *snap =
		(struct fstatfs_post_state *) rec->post_state;
	struct statfs first, recheck;
	int fd;
	int diverged = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_fstatfs: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->buf == 0)
		goto out_free;

	fd = (int) snap->fd;

	{
		void *buf = (void *)(unsigned long) snap->buf;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner buf
		 * field.  Reject pid-scribbled buf before deref.
		 */
		if (looks_like_corrupted_ptr(rec, buf)) {
			outputerr("post_fstatfs: rejected suspicious buf=%p (post_state-scribbled?)\n",
				  buf);
			goto out_free;
		}
	}

	memcpy(&first, (void *)(unsigned long) snap->buf, sizeof(first));

	if (syscall(SYS_fstatfs, fd, &recheck) != 0)
		goto out_free;

	if (first.f_type    != recheck.f_type)    diverged = 1;
	if (first.f_bsize   != recheck.f_bsize)   diverged = 1;
	if (first.f_blocks  != recheck.f_blocks)  diverged = 1;
	if (first.f_files   != recheck.f_files)   diverged = 1;
	if (first.f_namelen != recheck.f_namelen) diverged = 1;
	if (first.f_frsize  != recheck.f_frsize)  diverged = 1;
	if (first.f_flags   != recheck.f_flags)   diverged = 1;
	if (first.f_fsid.__val[0] != recheck.f_fsid.__val[0]) diverged = 1;
	if (first.f_fsid.__val[1] != recheck.f_fsid.__val[1]) diverged = 1;

	if (!diverged)
		goto out_free;

	output(0,
	       "fstatfs oracle anomaly: fd=%d "
	       "first={type=%lx,bsize=%ld,blocks=%llu,files=%llu,"
	       "namelen=%ld,frsize=%ld,flags=%lx,fsid=%x:%x} "
	       "recall={type=%lx,bsize=%ld,blocks=%llu,files=%llu,"
	       "namelen=%ld,frsize=%ld,flags=%lx,fsid=%x:%x}\n",
	       fd,
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

	__atomic_add_fetch(&shm->stats.fstatfs_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_fstatfs = {
	.name = "fstatfs",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "fd", [1] = "buf" },
	.sanitise = sanitise_fstatfs,
	.post = post_fstatfs,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(fstatfs64, unsigned int, fd, size_t, sz, struct statfs64 __user *, buf)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */

#ifdef SYS_fstatfs64
/*
 * Snapshot of the three fstatfs64 input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives
 * in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot retarget the re-issue at a
 * different fd, smear the buffer-size word used to seed the re-issue,
 * or steer the source memcpy at a foreign user buffer.
 */
struct fstatfs64_post_state {
	unsigned long fd;
	unsigned long sz;
	unsigned long buf;
};
#endif

static void sanitise_fstatfs64(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a3, rec->a2 ? rec->a2 : page_size);

#ifdef SYS_fstatfs64
	{
		struct fstatfs64_post_state *snap;

		rec->post_state = 0;

		/*
		 * Snapshot the three input args for the post oracle.
		 * Without this the post handler reads rec->aN at post-time,
		 * when a sibling syscall may have scribbled the slots:
		 * looks_like_corrupted_ptr() cannot tell a real-but-wrong
		 * heap address from the original user buf pointer, so the
		 * source memcpy would touch a foreign allocation, and a
		 * stomped fd or sz word would silently steer the re-issue
		 * against a different mount or change the buffer-size
		 * semantics.  post_state is private to the post handler.
		 */
		snap = zmalloc(sizeof(*snap));
		snap->fd  = rec->a1;
		snap->sz  = rec->a2;
		snap->buf = rec->a3;
		rec->post_state = (unsigned long) snap;
	}
#endif
}

/*
 * Oracle: fstatfs64(fd, sz, buf) is the explicit-size sibling of
 * fstatfs.  The struct shape is the same (struct statfs64, typically
 * 88 bytes on x86_64); the only wire difference is the sz argument
 * the caller passes to identify the buffer length.  The kernel
 * rejects any sz that does not match its own sizeof(struct statfs64)
 * with -EINVAL, so once we have gated on retval == 0 we know the
 * caller-supplied sz matches the kernel's expected size and the full
 * struct was filled.
 *
 * The same eight stable fields apply for the same reasons as fstatfs:
 * f_type, f_bsize, f_blocks, f_files, f_namelen, f_frsize, f_flags,
 * and the two halves of f_fsid.  f_bfree, f_bavail, f_ffree drift
 * legitimately under sibling allocator activity and stay excluded;
 * f_spare[] is reserved padding with no contract.
 *
 * Re-issue the syscall with the original sz so the recheck mirrors
 * the original call exactly — if a sibling closes the fd between the
 * two calls the recheck returns -EBADF and we benign-skip the
 * sample.  ONE_IN(100) sampling, single counter bump per anomalous
 * sample, no early-return on first divergence so multi-field damage
 * surfaces in one log line.
 *
 * fstatfs64 is a 32-bit-compat-only syscall — the syscall number is
 * not defined on x86_64 and other LP64 archs that fold the fstatfs
 * and fstatfs64 entry points together.  Gate the recheck on
 * SYS_fstatfs64 being present so the file still compiles on those
 * archs; the syscall table on those builds never reaches
 * syscall_fstatfs64 anyway, so the .post hook is unreachable in
 * practice.
 */
#ifdef SYS_fstatfs64
static void post_fstatfs64(struct syscallrecord *rec)
{
	struct fstatfs64_post_state *snap =
		(struct fstatfs64_post_state *) rec->post_state;
	struct statfs64 first, recheck;
	int fd;
	size_t sz;
	int diverged = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_fstatfs64: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->buf == 0)
		goto out_free;

	fd = (int) snap->fd;
	sz = (size_t) snap->sz;

	{
		void *buf = (void *)(unsigned long) snap->buf;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner buf
		 * field.  Reject pid-scribbled buf before deref.
		 */
		if (looks_like_corrupted_ptr(rec, buf)) {
			outputerr("post_fstatfs64: rejected suspicious buf=%p (post_state-scribbled?)\n",
				  buf);
			goto out_free;
		}
	}

	memcpy(&first, (void *)(unsigned long) snap->buf, sizeof(first));

	if (syscall(SYS_fstatfs64, fd, sz, &recheck) != 0)
		goto out_free;

	if (first.f_type    != recheck.f_type)    diverged = 1;
	if (first.f_bsize   != recheck.f_bsize)   diverged = 1;
	if (first.f_blocks  != recheck.f_blocks)  diverged = 1;
	if (first.f_files   != recheck.f_files)   diverged = 1;
	if (first.f_namelen != recheck.f_namelen) diverged = 1;
	if (first.f_frsize  != recheck.f_frsize)  diverged = 1;
	if (first.f_flags   != recheck.f_flags)   diverged = 1;
	if (first.f_fsid.__val[0] != recheck.f_fsid.__val[0]) diverged = 1;
	if (first.f_fsid.__val[1] != recheck.f_fsid.__val[1]) diverged = 1;

	if (!diverged)
		goto out_free;

	output(0,
	       "fstatfs64 oracle anomaly: fd=%d sz=%zu "
	       "first={type=%lx,bsize=%ld,blocks=%llu,files=%llu,"
	       "namelen=%ld,frsize=%ld,flags=%lx,fsid=%x:%x} "
	       "recall={type=%lx,bsize=%ld,blocks=%llu,files=%llu,"
	       "namelen=%ld,frsize=%ld,flags=%lx,fsid=%x:%x}\n",
	       fd, sz,
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

	__atomic_add_fetch(&shm->stats.fstatfs64_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_free:
	deferred_freeptr(&rec->post_state);
}
#endif

struct syscallentry syscall_fstatfs64 = {
	.name = "fstatfs64",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_LEN, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "fd", [1] = "sz", [2] = "buf" },
	.sanitise = sanitise_fstatfs64,
#ifdef SYS_fstatfs64
	.post = post_fstatfs64,
#endif
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
