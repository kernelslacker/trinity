/*
 * mount_churn - rapid mount/umount cycles in a private mount namespace
 * to exercise superblock alloc/free, mount tree linkage, and the
 * deactivate_super RCU/refcount machinery.
 *
 * fs_lifecycle (childops/fs-lifecycle.c) drives a full mount→use→umount
 * sequence per invocation, with significant time spent on per-fs file
 * operations (fallocate, xattr, copy_file_range, ...).  mount_churn
 * cuts the use phase entirely: each cycle is mount→umount with no IO
 * in between, so per-invocation throughput is dominated by the mount
 * syscall itself.  That keeps sustained pressure on the paths
 * fs_lifecycle visits only sporadically:
 *   - alloc_super / deactivate_super
 *   - sget_fc / get_tree_nodev superblock cache lookups
 *   - mnt_alloc / mnt_release and the mount-list locking under
 *     namespace_sem
 *   - tmpfs/proc/sysfs ->kill_sb teardown back-to-back
 *
 * Per invocation: 1..MAX_CYCLES cycles.  Each cycle picks one of
 * tmpfs/proc/sysfs (always present) or ext4 (only when the parent's
 * scratch_block pool published a loop-backed slot) and a random subset
 * of the safe MS_* flag set.
 *
 * Bounded to a private mount namespace.  When the parent provisioned
 * one at startup (shm->isolation.mnt_ready latched -- root-started,
 * --no-startup-isolation unset, unshare(CLONE_NEWNS) plus the
 * MS_REC|MS_PRIVATE remount of '/' both succeeded) we inherit it via
 * fork() and skip the per-child unshare entirely.  When the latch is
 * false (non-root, opt-out, EPERM/ENOSYS at parent setup) we fall back
 * to the per-child unshare(CLONE_NEWNS) + MS_REC|MS_PRIVATE remount of
 * '/' byte-for-byte, exactly as before the gate existed; unshare or
 * remount failure latches the op off for the rest of this child.
 *
 * EPERM handling on the per-cycle mount() differs between the two
 * paths.  On the fallback path EPERM means the per-child unshare gave
 * us a private mount-ns but not the caps to mount in it -- a
 * persistent state -- so we latch the op off as before.  On the
 * inherited path EPERM is the expected post-drop_privs steady state
 * (child = nobody, no CAP_SYS_ADMIN in the init user-ns owning the
 * parent's mount-ns); we count-but-tolerate so the kernel-side
 * arg-parse coverage the syscall reaches before may_mount() rejects
 * (copy_mount_string for the type/dev/data, flag-mask validation,
 * LSM security_sb_mount, LOOKUP_FOLLOW on the target) keeps landing
 * on every invocation.
 *
 * ext4 path source is a /dev/loopN drawn from the scratch_block pool
 * (fds/scratch_block.c) -- itself gated on mnt_ready.  Every loop
 * number in the pool came from the kernel's own LOOP_CTL_GET_FREE so
 * a host disk node cannot enter the mount() call by construction.
 * When the pool has no loop entry (mnt_ready false, /dev/loop-control
 * absent, mkfs.ext4 missing) ext4 silently drops out of the per-cycle
 * pick set and the invocation behaves identically to the pre-pool
 * three-fstype run.
 *
 * Flag set is curated to the subset that's safe to combine freely with
 * the chosen fstype: MS_NOEXEC, MS_NOSUID, MS_NODEV, MS_RDONLY,
 * MS_NOATIME, MS_NODIRATIME, MS_RELATIME, MS_SYNCHRONOUS.  Deliberately
 * excluded: MS_BIND (needs a source), MS_MOVE (rearranges live tree),
 * MS_REMOUNT (changes options on existing mount; not what this op is
 * about), MS_SHARED/PRIVATE/SLAVE/UNBINDABLE (propagation control,
 * already handled by the namespace setup), MS_REC (nothing to recurse
 * into on a fresh mount).
 *
 * Self-bounding: the inner loop is hard-capped at MAX_CYCLES, every
 * mount is matched by an immediate umount2(MNT_DETACH) attempt (or a
 * graceful skip if mount failed), and the alarm(1) the parent arms
 * before dispatch bounds wall-clock time.  Per-(pid, counter) base
 * paths so concurrent children don't collide.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "scratch_block.h"
#include "shm.h"
#include "syscall-gate.h"
#include "trinity.h"
#include "utils.h"	/* ARRAY_SIZE */

/* New-mount-API constants.  Defined locally so the build does not
 * require a current <linux/mount.h>; the syscalls themselves are
 * available on every kernel trinity targets (fsopen landed in 5.2). */
#ifndef FSOPEN_CLOEXEC
#define FSOPEN_CLOEXEC		0x00000001
#endif
#ifndef FSMOUNT_CLOEXEC
#define FSMOUNT_CLOEXEC		0x00000001
#endif
#ifndef FSCONFIG_SET_FLAG
#define FSCONFIG_SET_FLAG	0
#endif
#ifndef FSCONFIG_SET_STRING
#define FSCONFIG_SET_STRING	1
#endif
#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE	6
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH	0x00000004
#endif
#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY	0x00000001
#endif
#ifndef MOUNT_ATTR_NOSUID
#define MOUNT_ATTR_NOSUID	0x00000002
#endif
#ifndef MOUNT_ATTR_NODEV
#define MOUNT_ATTR_NODEV	0x00000004
#endif
#ifndef MOUNT_ATTR_NOEXEC
#define MOUNT_ATTR_NOEXEC	0x00000008
#endif

#if defined(__NR_fsopen) && defined(__NR_fsconfig) && \
    defined(__NR_fsmount) && defined(__NR_move_mount)
#define HAVE_FSOPEN_QUARTET	1
#endif

/* Hard cap on mount/umount cycles per invocation.  Kept modest so a
 * single op completes well inside the alarm(1) window even when the
 * VFS is under contention from sibling churners. */
#define MAX_CYCLES	16

/* Latched once this child has a private mount namespace to operate
 * in -- either inherited from the parent's pre-fork unshare(CLONE_
 * NEWNS) + MS_REC|MS_PRIVATE remount of '/' (shm->isolation.mnt_ready
 * latched) or obtained via a per-child unshare(CLONE_NEWNS) +
 * MS_PRIVATE remount on the fallback path.  No need to re-attempt
 * setup once it succeeded -- the namespace is inherited across
 * subsequent invocations within this child. */
static bool ns_ready;
/* Distinguishes the source of ns_ready: true iff we inherited the
 * parent-provisioned mount-ns (shm->isolation.mnt_ready was set at
 * the time ensure_private_ns() first ran).  Gates the EPERM-on-mount
 * latch below so a child = nobody EPERM does not silently disable the
 * op when the parent's provisioning is in place. */
static bool ns_inherited;
/* Latched on the fallback path: per-child unshare(CLONE_NEWNS) /
 * MS_PRIVATE remount failed, or a per-cycle mount() returned EPERM
 * indicating the unshared namespace gave us no caps to mount in it.
 * Never latches on the inherited path -- there EPERM is expected
 * and the kernel arg-parse coverage before the may_mount() check is
 * the point. */
static bool ns_unsupported;

/* Per-process monotonic counter so each mountpoint name within a
 * child is distinct.  Doesn't need to be atomic — only this child
 * uses it. */
static unsigned long mount_churn_seq;

/* Always-present fstype set: no block backing required, no scratch
 * pool draw -- these mount strings double as their own source.
 * Ordering is load-bearing: the per-cycle pick passes the index
 * directly to fstypes[], and the per-invocation ext4_available probe
 * appends ext4 as a virtual entry at index ARRAY_SIZE(fstypes). */
static const char * const fstypes[] = {
	"tmpfs",
	"proc",
	"sysfs",
};

/* Safe flag set: each is a per-mount option that does not change the
 * shape of the mount tree and combines freely with fresh tmpfs/proc/
 * sysfs mounts. */
static const unsigned long safe_flags[] = {
	MS_NOEXEC,
	MS_NOSUID,
	MS_NODEV,
	MS_RDONLY,
	MS_NOATIME,
	MS_NODIRATIME,
	MS_RELATIME,
	MS_SYNCHRONOUS,
};

static unsigned long pick_flags(void)
{
	unsigned long flags = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(safe_flags); i++) {
		if (RAND_BOOL())
			flags |= safe_flags[i];
	}
	/* MS_NOATIME and MS_RELATIME are mutually exclusive; if both got
	 * picked, drop MS_RELATIME so the kernel doesn't reject the
	 * mount with EINVAL on every other invocation. */
	if ((flags & MS_NOATIME) && (flags & MS_RELATIME))
		flags &= ~MS_RELATIME;
	return flags;
}

static bool ensure_private_ns(struct childdata *child)
{
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_ready)
		return true;
	if (ns_unsupported)
		return false;

	/* Inherited path: the parent unshared CLONE_NEWNS and remounted
	 * '/' MS_REC|MS_PRIVATE before fork(), and we are already inside
	 * that namespace by inheritance.  Latch ns_inherited so the
	 * per-cycle EPERM handling does not disable the op on the
	 * expected post-drop_privs cap-block. */
	if (__atomic_load_n(&shm->isolation.mnt_ready, __ATOMIC_RELAXED)) {
		ns_inherited = true;
		ns_ready = true;
		return true;
	}

	/* Fallback path: per-child unshare + MS_PRIVATE remount, byte-
	 * for-byte the pre-gate code.  EPERM here is the non-root host
	 * execution case and latches the op off for this child. */
	if (unshare(CLONE_NEWNS) != 0) {
		ns_unsupported = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop_latch_reason[op],
					 CHILDOP_LATCH_INIT_FAILED,
					 __ATOMIC_RELAXED);
		return false;
	}

	if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
		ns_unsupported = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop_latch_reason[op],
					 CHILDOP_LATCH_INIT_FAILED,
					 __ATOMIC_RELAXED);
		outputerr("mount_churn: MS_PRIVATE remount failed (errno=%d), disabling\n",
		          errno);
		return false;
	}

	ns_ready = true;
	return true;
}

#ifdef HAVE_FSOPEN_QUARTET
/* Filesystems suitable for an fsopen() probe.  tmpfs/ramfs are
 * universally built; bpf/proc/sysfs are present in any non-trivial
 * kernel.  The kernel-side fsopen→fsconfig→fsmount parse and the
 * subsequent inode-timestamp path (current_time on every namei
 * mutation) is the coverage target; an fstype that rejects symlink
 * creation just exits the inner churn after the first errored op
 * without disturbing the rest of the cycle. */
static const char * const fsopen_fstypes[] = {
	"tmpfs",
	"ramfs",
	"bpf",
	"proc",
	"sysfs",
};

/* Drive the dirfd-on-the-fsmount-fd path that lands in the kernel
 * namei + inode_update_time machinery.  Each symlinkat publishes a
 * fresh dentry; the unlinkat-through-the-symlink walks "name/../name"
 * which forces a path resolution that touches the parent inode's
 * timestamps via current_time -- the inode-timestamp update
 * path.  Iterations are hard-capped; the loop exits on the first
 * fatal error (EPERM/EROFS/EINVAL on an fstype that rejects
 * symlinks). */
static void fsopen_path_churn(int mnt_fd, unsigned long seq)
{
	const unsigned int iters = 1U + rnd_modulo_u32(8U);
	unsigned int i;

	for (i = 0; i < iters; i++) {
		char name[32];
		char nested[96];

		(void)snprintf(name, sizeof(name),
			       "file%lu_%u", seq, i);
		(void)snprintf(nested, sizeof(nested),
			       "file%lu_%u/../file%lu_%u/file%lu_%u",
			       seq, i, seq, i, seq, i);

		if (symlinkat(".", mnt_fd, name) != 0)
			return;

		(void)unlinkat(mnt_fd, nested, 0);
		(void)unlinkat(mnt_fd, name, 0);
	}
}

static void fsopen_mount_cycle(void)
{
	const char *type;
	int fs_fd;
	int mnt_fd;
	unsigned int fsopen_flags;
	unsigned int fsmount_flags;
	unsigned int attr_flags = 0;
	unsigned long seq;
	pid_t pid;
	char path[PATH_MAX + 64];
	bool moved = false;

	type = fsopen_fstypes[rnd_modulo_u32(ARRAY_SIZE(fsopen_fstypes))];
	fsopen_flags = RAND_BOOL() ? FSOPEN_CLOEXEC : 0U;

	fs_fd = (int)trinity_raw_syscall(__NR_fsopen, type, fsopen_flags);
	if (fs_fd < 0) {
		__atomic_add_fetch(&shm->stats.mount_churn_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/* Exercise the per-parameter fsconfig() arms before the CREATE.
	 * Most fstypes will reject these key strings -- the point is to
	 * land in the fs_parser dispatch, not to succeed. */
	if (RAND_BOOL())
		(void)trinity_raw_syscall(__NR_fsconfig, fs_fd,
					  FSCONFIG_SET_STRING, "source",
					  type, 0);
	if (RAND_BOOL())
		(void)trinity_raw_syscall(__NR_fsconfig, fs_fd,
					  FSCONFIG_SET_FLAG, "ro",
					  NULL, 0);

	if (trinity_raw_syscall(__NR_fsconfig, fs_fd,
				FSCONFIG_CMD_CREATE, NULL, NULL, 0) != 0) {
		__atomic_add_fetch(&shm->stats.mount_churn_failed,
				   1, __ATOMIC_RELAXED);
		close(fs_fd);
		return;
	}

	fsmount_flags = RAND_BOOL() ? FSMOUNT_CLOEXEC : 0U;
	if (RAND_BOOL())
		attr_flags |= MOUNT_ATTR_RDONLY;
	if (RAND_BOOL())
		attr_flags |= MOUNT_ATTR_NOSUID;
	if (RAND_BOOL())
		attr_flags |= MOUNT_ATTR_NODEV;
	if (RAND_BOOL())
		attr_flags |= MOUNT_ATTR_NOEXEC;

	mnt_fd = (int)trinity_raw_syscall(__NR_fsmount, fs_fd,
					  fsmount_flags, attr_flags);
	close(fs_fd);
	if (mnt_fd < 0) {
		__atomic_add_fetch(&shm->stats.mount_churn_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	__atomic_add_fetch(&shm->stats.mount_churn_mounts,
			   1, __ATOMIC_RELAXED);

	seq = ++mount_churn_seq;
	pid = mypid();

	/* 1-in-4: graft the detached fsmount fd into the namespace via
	 * move_mount(MOVE_MOUNT_F_EMPTY_PATH).  The kernel grafts on a
	 * path it hasn't seen before (vs. the legacy mount() path the
	 * rest of this op drives), and the umount2() teardown follows
	 * the deactivate_super RCU machinery from a known-good
	 * starting point. */
	if (rnd_modulo_u32(4U) == 0U) {
		(void)snprintf(path, sizeof(path),
			       "%s/trinity-fsmount-%d-%lu",
			       trinity_tmpdir_abs(), (int)pid, seq);
		if (mkdir(path, 0755) == 0 &&
		    trinity_raw_syscall(__NR_move_mount, mnt_fd, "",
					AT_FDCWD, path,
					MOVE_MOUNT_F_EMPTY_PATH) == 0)
			moved = true;
	}

	fsopen_path_churn(mnt_fd, seq);

	if (moved) {
		if (umount2(path, MNT_DETACH) == 0)
			__atomic_add_fetch(&shm->stats.mount_churn_umounts,
					   1, __ATOMIC_RELAXED);
		(void)rmdir(path);
	}

	close(mnt_fd);
}
#endif /* HAVE_FSOPEN_QUARTET */

bool mount_churn(struct childdata *child)
{
	unsigned int cycles;
	unsigned int i;
	unsigned int pick_modulo;
	unsigned int fsopen_idx;
	bool ext4_available = false;
	pid_t pid = mypid();
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.mount_churn_runs, 1, __ATOMIC_RELAXED);

	if (!ensure_private_ns(child))
		return true;
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop_setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* Probe the scratch_block pool once per invocation: when the
	 * parent provisioned mnt_ready AND a loop-backed ext4 image
	 * survived setup we can drive real-fs mount cycles against
	 * /dev/loopN as the mount source.  The probe short-circuits on
	 * mnt_ready false so the fallback path issues zero pool reads
	 * and the per-cycle RNG draws are bit-identical to the pre-gate
	 * code.  When unavailable (non-root, mnt_ready degraded,
	 * /dev/loop-control absent, mkfs.ext4 missing) ext4 silently
	 * drops out of the pick set. */
	if (__atomic_load_n(&shm->isolation.mnt_ready, __ATOMIC_RELAXED) &&
	    scratch_block_random_loop_num() >= 0)
		ext4_available = true;

	pick_modulo = ARRAY_SIZE(fstypes) + (ext4_available ? 1U : 0U);
	fsopen_idx = pick_modulo;
#ifdef HAVE_FSOPEN_QUARTET
	pick_modulo++;
#endif
	cycles = 1 + rnd_modulo_u32(MAX_CYCLES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop_data_path[op],
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < cycles; i++) {
		const char *fstype;
		const char *source;
		char source_buf[32];
		unsigned int pick = rnd_modulo_u32(pick_modulo);
		unsigned long flags;
		unsigned long seq;
		char path[PATH_MAX + 64];

#ifdef HAVE_FSOPEN_QUARTET
		if (pick == fsopen_idx) {
			fsopen_mount_cycle();
			continue;
		}
#endif

		flags = pick_flags();
		seq = ++mount_churn_seq;

		if (pick < ARRAY_SIZE(fstypes)) {
			fstype = fstypes[pick];
			source = fstype;
		} else {
			/* ext4: source is /dev/loopN from the vetted
			 * pool.  Re-draw per cycle so successive ext4
			 * mounts hit different loop entries when the
			 * pool has more than one. */
			int loop_num = scratch_block_random_loop_num();

			if (loop_num < 0)
				continue;
			(void)snprintf(source_buf, sizeof(source_buf),
				       "/dev/loop%d", loop_num);
			fstype = "ext4";
			source = source_buf;
		}

		snprintf(path, sizeof(path),
			 "%s/trinity-mountchurn-%d-%lu",
			 trinity_tmpdir_abs(), (int)pid, seq);

		if (mkdir(path, 0755) != 0) {
			__atomic_add_fetch(&shm->stats.mount_churn_failed,
					   1, __ATOMIC_RELAXED);
			/* EEXIST is extremely unlikely with pid+seq
			 * names; ENOSPC/EROFS/EACCES on the cwd mean
			 * we can't even create mountpoints — bail. */
			if (errno == EROFS || errno == EACCES ||
			    errno == ENOSPC || errno == EPERM)
				return true;
			continue;
		}

		/* 1-in-RAND_NEGATIVE_RATIO sub the curated safe MS_* mask for
		 * an edge value — exercises sys_mount's flag-mask validation
		 * (MS_MGC magic, mutually-exclusive bits, unknown-bit
		 * rejection) which the safe subset above never reaches. */
		if (mount(source, path, fstype,
			  (unsigned long)RAND_NEGATIVE_OR(flags), NULL) != 0) {
			__atomic_add_fetch(&shm->stats.mount_churn_failed,
					   1, __ATOMIC_RELAXED);
			/* On the fallback path EPERM means the per-child
			 * unshare gave us a namespace but not the caps to
			 * mount in it (e.g. unprivileged userns without
			 * the right bits) — latch and bail.  On the
			 * inherited path EPERM is the expected post-
			 * drop_privs cap-block (the parent's mount-ns is
			 * owned by the init user-ns and the child = nobody
			 * has no CAP_SYS_ADMIN in it); the kernel arg-
			 * parse + flag validation + LSM + target path
			 * lookup all ran before may_mount() rejected, which
			 * is exactly the coverage the un-defang unlocks --
			 * keep going so each cycle lands a fresh call.
			 * ENODEV: fstype not built into kernel; skip this
			 * iter and try a different one next time. */
			if (errno == EPERM && !ns_inherited) {
				ns_unsupported = true;
				if (valid_op)
					__atomic_store_n(&shm->stats.childop_latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
				(void)rmdir(path);
				return true;
			}
			(void)rmdir(path);
			continue;
		}

		__atomic_add_fetch(&shm->stats.mount_churn_mounts,
				   1, __ATOMIC_RELAXED);

		if (umount2(path, MNT_DETACH) == 0) {
			__atomic_add_fetch(&shm->stats.mount_churn_umounts,
					   1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.mount_churn_failed,
					   1, __ATOMIC_RELAXED);
			/* MNT_DETACH almost never fails for a freshly-
			 * created mount with no users, but if it does
			 * (EINVAL on a mount that vanished, EPERM on
			 * lockdown) leave the directory and move on —
			 * the next iteration uses a fresh name. */
		}

		(void)rmdir(path);
	}

	return true;
}
