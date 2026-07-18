/*
 * mount_churn - rapid mount/umount cycles in a private mount namespace
 * to exercise superblock alloc/free, mount tree linkage, and the
 * deactivate_super RCU/refcount machinery.
 *
 * fs_lifecycle (childops/fs/fs-lifecycle.c) drives a full mount→use→umount
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
 * fork() and run the per-cycle body directly in the persistent child.
 * When the latch is false (non-root, opt-out, EPERM/ENOSYS at parent
 * setup) we instead run the per-cycle body inside a transient
 * grandchild forked by userns_run_in_ns(CLONE_NEWNS): the grandchild
 * gains CAP_SYS_ADMIN inside an owned user namespace, enters a private
 * mount namespace, runs the cycles, and _exit()s -- the persistent
 * fuzz child keeps the host credential profile the cap-drop oracle
 * observes.  Helper -EPERM (hardened userns policy refused
 * CLONE_NEWUSER) latches the op off; transient setup failure (-EAGAIN)
 * skips the iteration without latching.
 *
 * EPERM on the per-cycle mount() is expected on either path and does
 * not latch: on the inherited path it is the post-drop_privs cap-block
 * (child = nobody, no CAP_SYS_ADMIN in the init user-ns owning the
 * parent's mount-ns); on the grandchild path the userns grants
 * CAP_SYS_ADMIN inside the owned userns but kernel paths that
 * ns_capable() against init_user_ns still reject.  Either way the
 * kernel-side arg-parse coverage the syscall reaches before
 * may_mount() rejects (copy_mount_string for the type/dev/data,
 * flag-mask validation, LSM security_sb_mount, LOOKUP_FOLLOW on the
 * target) keeps landing on every invocation.
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
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "kernel/mount.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "scratch_block.h"
#include "shm.h"
#include "syscall-gate.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "utils.h"	/* ARRAY_SIZE */

#if defined(__NR_fsopen) && defined(__NR_fsconfig) && \
    defined(__NR_fsmount) && defined(__NR_move_mount)
#define HAVE_FSOPEN_QUARTET	1
#endif

/* Hard cap on mount/umount cycles per invocation.  Kept modest so a
 * single op completes well inside the alarm(1) window even when the
 * VFS is under contention from sibling churners. */
#define MAX_CYCLES	16

/* Latched on the fallback path when userns_run_in_ns(CLONE_NEWNS)
 * returns -EPERM -- the kernel refused CLONE_NEWUSER (typically a
 * hardened policy: user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Persistent for the child's
 * lifetime: re-trying would just burn syscalls.  Never set on the
 * inherited path; never set by per-cycle mount() EPERM (those are
 * per-fstype / per-cred and the surrounding kernel arg-parse coverage
 * is the point). */
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

/*
 * Per-invocation context handed to mount_churn_iter().  When the
 * callback runs inside the userns_run_in_ns grandchild the struct
 * lives in the parent stack and is reachable from the grandchild
 * through the fork()-inherited address space.  ext4_available is
 * decided in the parent because the scratch_block loop pool is gated
 * on shm->isolation.mnt_ready (a parent-only condition); the
 * grandchild path never sees ext4 by construction.
 */
struct mount_churn_iter_ctx {
	struct childdata *child;
	bool ext4_available;
};

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
		__atomic_add_fetch(&shm->stats.mount_churn.failed,
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
		__atomic_add_fetch(&shm->stats.mount_churn.failed,
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
		__atomic_add_fetch(&shm->stats.mount_churn.failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	__atomic_add_fetch(&shm->stats.mount_churn.mounts,
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
			__atomic_add_fetch(&shm->stats.mount_churn.umounts,
					   1, __ATOMIC_RELAXED);
		(void)rmdir(path);
	}

	close(mnt_fd);
}
#endif /* HAVE_FSOPEN_QUARTET */

/*
 * Per-invocation body that runs inside a private mount namespace --
 * either inherited (called directly from the persistent fuzz child
 * when shm->isolation.mnt_ready is latched) or transient (called from
 * the userns_run_in_ns grandchild on the fallback path).  Return
 * value is ignored by userns_run_in_ns() and unused on the inherited
 * call.
 *
 * MS_REC|MS_PRIVATE remount of '/' is issued unconditionally and
 * voided: on the grandchild path the fresh mount-ns inherits the
 * host's propagation type and must be detached; on the inherited
 * path the parent already remounted MS_PRIVATE so the call EPERMs
 * harmlessly (no CAP_SYS_ADMIN in the init user-ns owning the parent's
 * mount-ns).  Either way the per-cycle mount/umount loop below runs
 * in a propagation-isolated tree.
 */
static int mount_churn_iter(void *arg)
{
	struct mount_churn_iter_ctx *ctx = (struct mount_churn_iter_ctx *)arg;
	struct childdata *child = ctx->child;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	unsigned int cycles;
	unsigned int i;
	unsigned int pick_modulo;
	unsigned int fsopen_idx;
	pid_t pid = mypid();

	(void)mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	pick_modulo = ARRAY_SIZE(fstypes) + (ctx->ext4_available ? 1U : 0U);
	fsopen_idx = pick_modulo;
#ifdef HAVE_FSOPEN_QUARTET
	pick_modulo++;
#endif
	cycles = 1 + rnd_modulo_u32(MAX_CYCLES);

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
			__atomic_add_fetch(&shm->stats.mount_churn.failed,
					   1, __ATOMIC_RELAXED);
			/* EEXIST is extremely unlikely with pid+seq
			 * names; ENOSPC/EROFS/EACCES on the cwd mean
			 * we can't even create mountpoints — bail. */
			if (errno == EROFS || errno == EACCES ||
			    errno == ENOSPC || errno == EPERM)
				return 0;
			continue;
		}

		/* 1-in-RAND_NEGATIVE_RATIO sub the curated safe MS_* mask for
		 * an edge value — exercises sys_mount's flag-mask validation
		 * (MS_MGC magic, mutually-exclusive bits, unknown-bit
		 * rejection) which the safe subset above never reaches. */
		if (mount(source, path, fstype,
			  (unsigned long)RAND_NEGATIVE_OR(flags), NULL) != 0) {
			__atomic_add_fetch(&shm->stats.mount_churn.failed,
					   1, __ATOMIC_RELAXED);
			/* EPERM here is the expected post-drop_privs cap-
			 * block on both paths: on the inherited path the
			 * parent's mount-ns is owned by init_user_ns and
			 * child = nobody has no CAP_SYS_ADMIN; on the
			 * grandchild path the owned userns grants
			 * CAP_SYS_ADMIN there but ns_capable() against
			 * init_user_ns still rejects mount() on host-
			 * scoped resources.  The kernel arg-parse + flag
			 * validation + LSM + target path lookup all ran
			 * before may_mount() rejected -- that is the
			 * coverage the un-defang unlocks -- so keep going.
			 * ENODEV: fstype not built into kernel; skip this
			 * iter and try a different one next time. */
			(void)rmdir(path);
			continue;
		}

		__atomic_add_fetch(&shm->stats.mount_churn.mounts,
				   1, __ATOMIC_RELAXED);

		if (umount2(path, MNT_DETACH) == 0) {
			__atomic_add_fetch(&shm->stats.mount_churn.umounts,
					   1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.mount_churn.failed,
					   1, __ATOMIC_RELAXED);
			/* MNT_DETACH almost never fails for a freshly-
			 * created mount with no users, but if it does
			 * (EINVAL on a mount that vanished, EPERM on
			 * lockdown) leave the directory and move on —
			 * the next iteration uses a fresh name. */
		}

		(void)rmdir(path);
	}

	return 0;
}

bool mount_churn(struct childdata *child)
{
	struct mount_churn_iter_ctx ctx;
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch slot.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.mount_churn.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	ctx.child = child;

	/* Inherited fast-path: the parent unshared CLONE_NEWNS and
	 * MS_REC|MS_PRIVATE-remounted '/' before fork() and the
	 * scratch_block pool is live, so we already own a private
	 * mount-ns and can probe the loop pool for an ext4 source.
	 * Run the per-cycle body directly in the persistent child --
	 * no grandchild fork, no userns -- preserving the cap-drop
	 * oracle's view of the host credential profile. */
	if (__atomic_load_n(&shm->isolation.mnt_ready, __ATOMIC_RELAXED)) {
		ctx.ext4_available = scratch_block_random_loop_num() >= 0;
		mount_churn_iter(&ctx);
		return true;
	}

	/* Fallback path: no parent-provisioned mount-ns.  Fork a
	 * transient grandchild via userns_run_in_ns(CLONE_NEWNS) so
	 * an unprivileged persistent child can still enter a private
	 * mount namespace and exercise the mount/umount cycle paths.
	 * ext4 is unavailable here because the scratch_block loop pool
	 * is gated on mnt_ready (parent-only); the grandchild path
	 * sticks to tmpfs/proc/sysfs. */
	ctx.ext4_available = false;

	rc = userns_run_in_ns(CLONE_NEWNS, mount_churn_iter, &ctx);
	if (rc == -EPERM) {
		/* Kernel refused CLONE_NEWUSER (hardened policy:
		 * user.max_user_namespaces=0 or
		 * kernel.unprivileged_userns_clone=0).  Latch and
		 * stop retrying for this child's lifetime. */
		ns_unsupported = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (-EAGAIN: fork,
		 * id-map write, secondary CLONE_NEWNS unshare).  Skip
		 * this invocation without latching -- the failure is
		 * not policy and may not recur. */
		__atomic_add_fetch(&shm->stats.mount_churn.failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
