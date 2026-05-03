/*
 * SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *, buf)
 */
#include <limits.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_statfs(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, page_size);
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
	char snap_path[PATH_MAX];
	struct statfs snap, recheck;
	int diverged = 0;

	if ((long) rec->retval != 0)
		return;

	if (rec->a1 == 0)
		return;

	if (rec->a2 == 0)
		return;

	if (!ONE_IN(100))
		return;

	strncpy(snap_path, (const char *)(unsigned long) rec->a1,
		sizeof(snap_path) - 1);
	snap_path[sizeof(snap_path) - 1] = '\0';
	memcpy(&snap, (void *)(unsigned long) rec->a2, sizeof(snap));

	if (syscall(SYS_statfs, snap_path, &recheck) != 0)
		return;

	if (snap.f_fsid.__val[0] != recheck.f_fsid.__val[0] ||
	    snap.f_fsid.__val[1] != recheck.f_fsid.__val[1])
		return;

	if (snap.f_type    != recheck.f_type)    diverged = 1;
	if (snap.f_bsize   != recheck.f_bsize)   diverged = 1;
	if (snap.f_blocks  != recheck.f_blocks)  diverged = 1;
	if (snap.f_files   != recheck.f_files)   diverged = 1;
	if (snap.f_namelen != recheck.f_namelen) diverged = 1;
	if (snap.f_frsize  != recheck.f_frsize)  diverged = 1;
	if (snap.f_flags   != recheck.f_flags)   diverged = 1;

	if (!diverged)
		return;

	output(0,
	       "statfs oracle anomaly: path=%s "
	       "first={type=%lx,bsize=%ld,blocks=%llu,files=%llu,"
	       "namelen=%ld,frsize=%ld,flags=%lx,fsid=%x:%x} "
	       "recall={type=%lx,bsize=%ld,blocks=%llu,files=%llu,"
	       "namelen=%ld,frsize=%ld,flags=%lx,fsid=%x:%x}\n",
	       snap_path,
	       (unsigned long) snap.f_type, (long) snap.f_bsize,
	       (unsigned long long) snap.f_blocks,
	       (unsigned long long) snap.f_files,
	       (long) snap.f_namelen, (long) snap.f_frsize,
	       (unsigned long) snap.f_flags,
	       (unsigned int) snap.f_fsid.__val[0],
	       (unsigned int) snap.f_fsid.__val[1],
	       (unsigned long) recheck.f_type, (long) recheck.f_bsize,
	       (unsigned long long) recheck.f_blocks,
	       (unsigned long long) recheck.f_files,
	       (long) recheck.f_namelen, (long) recheck.f_frsize,
	       (unsigned long) recheck.f_flags,
	       (unsigned int) recheck.f_fsid.__val[0],
	       (unsigned int) recheck.f_fsid.__val[1]);

	__atomic_add_fetch(&shm->stats.statfs_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);
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
};

/*
 * SYSCALL_DEFINE3(statfs64, const char __user *, pathname, size_t, sz, struct statfs64 __user *, buf)
 */

static void sanitise_statfs64(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a3, rec->a2 ? rec->a2 : page_size);
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
	char snap_path[PATH_MAX];
	struct statfs64 snap, recheck;
	size_t sz_snapshot;
	int diverged = 0;

	if ((long) rec->retval != 0)
		return;

	if (rec->a1 == 0)
		return;

	if (rec->a2 < sizeof(struct statfs64))
		return;

	if (rec->a3 == 0)
		return;

	if (!ONE_IN(100))
		return;

	sz_snapshot = (size_t) rec->a2;

	strncpy(snap_path, (const char *)(unsigned long) rec->a1,
		sizeof(snap_path) - 1);
	snap_path[sizeof(snap_path) - 1] = '\0';
	memcpy(&snap, (void *)(unsigned long) rec->a3, sizeof(snap));

	if (syscall(SYS_statfs64, snap_path, sz_snapshot, &recheck) != 0)
		return;

	if (snap.f_fsid.__val[0] != recheck.f_fsid.__val[0] ||
	    snap.f_fsid.__val[1] != recheck.f_fsid.__val[1])
		return;

	if (snap.f_type    != recheck.f_type)    diverged = 1;
	if (snap.f_bsize   != recheck.f_bsize)   diverged = 1;
	if (snap.f_blocks  != recheck.f_blocks)  diverged = 1;
	if (snap.f_files   != recheck.f_files)   diverged = 1;
	if (snap.f_namelen != recheck.f_namelen) diverged = 1;
	if (snap.f_frsize  != recheck.f_frsize)  diverged = 1;
	if (snap.f_flags   != recheck.f_flags)   diverged = 1;

	if (!diverged)
		return;

	output(0,
	       "statfs64 oracle anomaly: path=%s sz=%zu "
	       "first={type=%lx,bsize=%ld,blocks=%llu,files=%llu,"
	       "namelen=%ld,frsize=%ld,flags=%lx,fsid=%x:%x} "
	       "recall={type=%lx,bsize=%ld,blocks=%llu,files=%llu,"
	       "namelen=%ld,frsize=%ld,flags=%lx,fsid=%x:%x}\n",
	       snap_path, sz_snapshot,
	       (unsigned long) snap.f_type, (long) snap.f_bsize,
	       (unsigned long long) snap.f_blocks,
	       (unsigned long long) snap.f_files,
	       (long) snap.f_namelen, (long) snap.f_frsize,
	       (unsigned long) snap.f_flags,
	       (unsigned int) snap.f_fsid.__val[0],
	       (unsigned int) snap.f_fsid.__val[1],
	       (unsigned long) recheck.f_type, (long) recheck.f_bsize,
	       (unsigned long long) recheck.f_blocks,
	       (unsigned long long) recheck.f_files,
	       (long) recheck.f_namelen, (long) recheck.f_frsize,
	       (unsigned long) recheck.f_flags,
	       (unsigned int) recheck.f_fsid.__val[0],
	       (unsigned int) recheck.f_fsid.__val[1]);

	__atomic_add_fetch(&shm->stats.statfs64_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);
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
};
