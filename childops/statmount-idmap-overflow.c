/*
 * statmount_idmap_overflow - drive statmount() down the mnt_idmap
 * uid/gid map serialization path against a freshly-built idmapped
 * tmpfs mount, sweeping caller bufsize around the seq-buffer
 * overflow boundary.
 *
 * Background.  statmount(2) returns per-mount information into a
 * caller-supplied buffer; the variable tail of the response can
 * include the ASCII-rendered uid_map and gid_map of an attached
 * mnt_idmap when the caller asks for STATMOUNT_MNT_UIDMAP /
 * STATMOUNT_MNT_GIDMAP.  Rendering those tables walks the per-userns
 * id_map extents into a seq_buffer whose remaining capacity is
 * derived from (caller-supplied bufsize - already-emitted bytes); a
 * boundary bufsize is the interesting one because it lands the
 * remaining-capacity arithmetic exactly at zero just as a per-extent
 * snprintf is about to run, which is the seq-overflow accounting
 * arm.  Flat per-syscall fuzzing of statmount() never assembles the
 * prerequisite (an idmapped mount carrying a userns with a non-
 * trivial id_map), so syscalls/statmount.c iterates UIDMAP/GIDMAP
 * mask bits but the kernel-side per-mask copy_to_user arm sits
 * behind an idmap pointer that is always NULL.  This childop builds
 * the prerequisite shape directly.
 *
 * Bug-class targets (non-exhaustive):
 *   - seq-buffer accounting: per-extent emit at a remaining-capacity
 *     boundary; off-by-one between "fits exactly" and "overflows by
 *     one byte" historically reaches a one-byte slab OOB-write.
 *   - mask-vs-tail bookkeeping: STATMOUNT_SUPPORTED_MASK reporting
 *     of UIDMAP/GIDMAP must remain consistent with whether the tail
 *     actually rendered them under an overflow truncation.
 *   - lifetime: the userns_fd attached via mount_setattr() holds a
 *     reference on the source userns; closing the userns_fd while
 *     statmount() is mid-walk exercises that reference.
 *
 * Shape (per outer iteration, BUDGETED+capped):
 *   1. First call per process probes statmount() / mount_setattr() /
 *      fsopen() / fsmount() availability (the new-mount-API quartet);
 *      a missing syscall (ENOSYS) latches the op off for the rest of
 *      the child's life.  Per invocation, the outer bufsize-sweep
 *      loop runs inside a transient grandchild forked by
 *      userns_run_in_ns(): the helper installs an identity user
 *      namespace plus a fresh CLONE_NEWNS, runs the loop, and
 *      _exit()s -- the kernel reaps every mount, fd, and sibling
 *      fork (the carrier in step 2) with the grandchild's namespace
 *      stack.  The persistent fuzz child never mutates its own
 *      credentials or namespaces, so the cap-drop oracle keeps
 *      observing the host credential profile.  Helper -EPERM
 *      (hardened userns policy refused CLONE_NEWUSER) latches the
 *      op off uniformly; helper -1 (transient setup failure: fork,
 *      id-map write, secondary CLONE_NEWNS unshare) skips the
 *      invocation without latching.
 *   2. Build a "carrier" child userns: fork a sibling that unshares
 *      CLONE_NEWUSER and pauses; the parent writes "deny" to the
 *      sibling's setgroups, then a one-line uid_map and gid_map
 *      mapping the caller's outer uid/gid into id 0 inside the
 *      sibling.  (A single extent is the floor an unprivileged
 *      caller can install in its own child userns; the bug class
 *      cares about the seq-buffer accounting arm, which a one-
 *      extent map drives just as well as a deeper map once bufsize
 *      lands on the boundary.)  The parent opens /proc/<pid>/ns/user
 *      to capture the userns_fd, SIGTERMs the carrier, and reaps it.
 *   3. Create a detached tmpfs source via fsopen("tmpfs") +
 *      fsconfig(CMD_CREATE) + fsmount(); the resulting mount fd is
 *      never moved into the host hierarchy, so the source mount is
 *      visible only via the fd we hold.
 *   4. mount_setattr(mount_fd, "", AT_EMPTY_PATH, {attr_set =
 *      MOUNT_ATTR_IDMAP, userns_fd = carrier}, sizeof) installs the
 *      idmap on the detached mount.
 *   5. Sweep statmount(STATMOUNT_BY_FD, mask = MNT_BASIC | MNT_UIDMAP
 *      | MNT_GIDMAP | SUPPORTED_MASK, buf, bufsize, ...) across a
 *      bounded set of bufsizes -- a few large-enough sizes for the
 *      success arm, plus a sweep of small sizes around
 *      sizeof(struct statmount) where the variable-tail render is
 *      forced to truncate.  Every step failure is coverage, not a
 *      childop failure; we just bump a stat.
 *   6. Close mount_fd and userns_fd before the next iter so an
 *      outer-loop burn doesn't accumulate detached mounts.
 *
 * Self-gating.  Two latches.
 *   - statmount_idmap_unsupported: the first invocation probes the
 *     new-mount-API quartet; a missing syscall (ENOSYS) or a
 *     persistent ENOSYS from statmount itself latches the op off
 *     uniformly.  Same shape as the qrtr / pfkey / l2tp latches.
 *   - ns_unshare_failed_statmount_idmap: latched when
 *     userns_run_in_ns() returns -EPERM, meaning the transient
 *     grandchild's unshare(CLONE_NEWUSER) was refused by a hardened
 *     userns policy (user.max_user_namespaces=0 or
 *     kernel.unprivileged_userns_clone=0).  Helper -1 (transient
 *     setup failure: fork, id-map write, secondary CLONE_NEWNS
 *     unshare) does NOT set this latch -- the failure is not policy
 *     and may not recur on the next invocation.
 *
 * Box-safety.  All mount work executes inside a transient grandchild
 * forked by userns_run_in_ns(); the grandchild holds an identity
 * user namespace plus a fresh CLONE_NEWNS and _exit()s when the
 * outer-loop callback returns, so the kernel reaps every mount,
 * file descriptor, and sibling fork the loop created with the
 * grandchild's namespace stack.  The persistent fuzz child never
 * mutates its own credentials or namespaces.  Nothing touches the
 * host mount table, nothing is moved into the host hierarchy, and
 * the backing tmpfs is created via the detached new-mount-API
 * (fsopen + fsmount) so the source mount lives only behind a file
 * descriptor the grandchild holds for its lifetime.  No module
 * load, no rtnetlink, no globally-reachable resource.  Bounded
 * outer loop with a hard wall-clock cap; per-iter bufsize sweep is
 * a fixed small table.
 *
 * Header compat.  Modern <linux/mount.h> ships struct mount_attr,
 * MOUNT_ATTR_IDMAP, the fsconfig enum, struct mnt_id_req, struct
 * statmount, and the STATMOUNT_* mask bits including UIDMAP/GIDMAP
 * and the BY_FD flag.  Stripped sysroots get __has_include-guarded
 * fallback constants; the new-mount-API syscall numbers are
 * referenced via __NR_* and a missing number latches the op off.
 */

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "syscall-gate.h"
#include "childops-util.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#if __has_include(<linux/mount.h>)
#include <linux/mount.h>
#endif

/*
 * UAPI fallbacks.  Stripped sysroots may not ship the new-mount-API
 * surface; the numeric values below match include/uapi/linux/mount.h
 * (stable since v5.2 for fsopen/fsmount, v5.12 for MOUNT_ATTR_IDMAP,
 * v6.8 for statmount, v7.0 for STATMOUNT_MNT_UIDMAP /
 * STATMOUNT_MNT_GIDMAP / STATMOUNT_BY_FD).
 */
#ifndef MOUNT_ATTR_IDMAP
#define MOUNT_ATTR_IDMAP		0x00100000
#endif

#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE		6
#endif

#ifndef STATMOUNT_MNT_BASIC
#define STATMOUNT_MNT_BASIC		0x00000002U
#endif
#ifndef STATMOUNT_SUPPORTED_MASK
#define STATMOUNT_SUPPORTED_MASK	0x00001000U
#endif
#ifndef STATMOUNT_MNT_UIDMAP
#define STATMOUNT_MNT_UIDMAP		0x00002000U
#endif
#ifndef STATMOUNT_MNT_GIDMAP
#define STATMOUNT_MNT_GIDMAP		0x00004000U
#endif
#ifndef STATMOUNT_BY_FD
#define STATMOUNT_BY_FD			0x00000001U
#endif

#if !__has_include(<linux/mount.h>)
struct mount_attr {
	__u64	attr_set;
	__u64	attr_clr;
	__u64	propagation;
	__u64	userns_fd;
};

struct statmount {
	__u32	size;
	__u32	mnt_opts;
	__u64	mask;
	__u32	sb_dev_major;
	__u32	sb_dev_minor;
	__u64	sb_magic;
	__u32	sb_flags;
	__u32	fs_type;
	__u64	mnt_id;
	__u64	mnt_parent_id;
	__u32	mnt_id_old;
	__u32	mnt_parent_id_old;
	__u64	mnt_attr;
	__u64	mnt_propagation;
	__u64	mnt_peer_group;
	__u64	mnt_master;
	__u64	propagate_from;
	__u32	mnt_root;
	__u32	mnt_point;
	__u64	mnt_ns_id;
	__u32	fs_subtype;
	__u32	sb_source;
	__u32	opt_num;
	__u32	opt_array;
	__u32	opt_sec_num;
	__u32	opt_sec_array;
	__u64	supported_mask;
	__u32	mnt_uidmap_num;
	__u32	mnt_uidmap;
	__u32	mnt_gidmap_num;
	__u32	mnt_gidmap;
	__u64	__spare2[44];
	char	str[];
};
#endif /* !__has_include(<linux/mount.h>) */

/*
 * Request struct for statmount() / listmount().  Defined locally with
 * the v1 UAPI layout (union { __u32 mnt_ns_fd; __u32 mnt_fd; } at
 * offset 4) regardless of whether <linux/mount.h> is available,
 * because older build headers still ship the v0 layout that names
 * offset 4 as "__u32 spare".  The kernel BY_FD path requires the
 * mount fd at offset 4 with both mnt_id and mnt_ns_id zero
 * (fs/namespace.c rejects BY_FD requests with either set), so the
 * file uses this private name to keep the layout under our control.
 */
struct mnt_id_req_v1 {
	__u32	size;
	union {
		__u32	mnt_ns_fd;
		__u32	mnt_fd;
	};
	__u64	mnt_id;
	__u64	param;
	__u64	mnt_ns_id;
};

/*
 * Outer-loop sizing.  Per-iter cost is one fork/exit pair (the
 * userns carrier), one fsopen/fsconfig/fsmount triple, one
 * mount_setattr, then a small fixed sweep of statmount() calls.  Cap
 * mirrors pfkey_spd_walk's outer cap so steady-state load is
 * comparable.
 */
#define STATMOUNT_IDMAP_OUTER_BASE	2U
#define STATMOUNT_IDMAP_OUTER_CAP	8U
#define STATMOUNT_IDMAP_WALL_CAP_NS	(250L * 1000L * 1000L)

/*
 * Bufsize sweep.  The first three entries are large-enough to land
 * the success arm; the rest sample around sizeof(struct statmount)
 * +/- a few bytes so the per-extent render in the variable tail is
 * forced to truncate at a remaining-capacity boundary.  Kept small
 * so a fast kernel doesn't loop indefinitely.
 */
static const unsigned long statmount_idmap_bufsizes[] = {
	8192UL,
	4096UL,
	1024UL,
	sizeof(struct statmount) + 64UL,
	sizeof(struct statmount) + 16UL,
	sizeof(struct statmount) + 1UL,
	sizeof(struct statmount),
	sizeof(struct statmount) - 1UL,
	sizeof(struct statmount) / 2UL,
	0UL,
};

/* Per-process latches.  The probe runs once; once any latch is set
 * the op becomes a silent no-op for the rest of the child's life. */
static bool statmount_idmap_probed;
static bool statmount_idmap_unsupported;
/* Latched per-child when userns_run_in_ns() reports -EPERM, meaning the
 * transient grandchild's unshare(CLONE_NEWUSER) was refused by a
 * hardened policy (user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private mount + user
 * namespace pair we cannot install the idmap on the detached tmpfs, so
 * the op stays disabled for the remainder of this child's lifetime.
 * Helper return -1 (transient setup failure) does NOT set this -- the
 * failure is not policy and may not recur on the next invocation. */
static bool ns_unshare_failed_statmount_idmap;

#if defined(__NR_statmount) && defined(__NR_mount_setattr) && \
    defined(__NR_fsopen) && defined(__NR_fsmount) && \
    defined(__NR_fsconfig)
#define HAVE_STATMOUNT_IDMAP_SYSCALLS 1
#endif

#ifdef HAVE_STATMOUNT_IDMAP_SYSCALLS

static long sys_fsopen(const char *fsname, unsigned int flags)
{
	return trinity_raw_syscall(__NR_fsopen, fsname, flags);
}

static long sys_fsconfig(int fd, unsigned int cmd, const char *key,
			 const void *value, int aux)
{
	return trinity_raw_syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}

static long sys_fsmount(int fd, unsigned int flags, unsigned int attr_flags)
{
	return trinity_raw_syscall(__NR_fsmount, fd, flags, attr_flags);
}

static long sys_mount_setattr(int dfd, const char *path, unsigned int flags,
			      struct mount_attr *attr, size_t size)
{
	return trinity_raw_syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
}

static long sys_statmount(struct mnt_id_req_v1 *req, struct statmount *buf,
			  size_t bufsize, unsigned int flags)
{
	return trinity_raw_syscall(__NR_statmount, req, buf, bufsize, flags);
}

/*
 * Probe the new-mount-API quartet plus statmount itself.  An
 * ENOSYS-class failure on any of them latches the op off uniformly;
 * a non-ENOSYS error (EINVAL, EBADF on the bogus probe fd) is
 * acceptable because it proves the syscall is dispatched.
 */
static void probe_statmount_idmap(void)
{
	long rc;

	statmount_idmap_probed = true;

	/* fsopen with an empty filesystem name returns -EINVAL on a
	 * kernel that knows the syscall, -ENOSYS otherwise. */
	rc = sys_fsopen("", 0);
	if (rc < 0 && errno == ENOSYS) {
		statmount_idmap_unsupported = true;
		return;
	}
	if (rc >= 0)
		close((int)rc);

	/* mount_setattr against an invalid fd returns -EBADF on a
	 * kernel that knows the syscall, -ENOSYS otherwise. */
	rc = sys_mount_setattr(-1, NULL, 0, NULL, 0);
	if (rc < 0 && errno == ENOSYS) {
		statmount_idmap_unsupported = true;
		return;
	}

	/* statmount with a NULL req returns -EFAULT on a kernel that
	 * knows the syscall, -ENOSYS otherwise. */
	rc = sys_statmount(NULL, NULL, 0, 0);
	if (rc < 0 && errno == ENOSYS) {
		statmount_idmap_unsupported = true;
		return;
	}
}

/*
 * Carrier child: unshare CLONE_NEWUSER, signal the parent that the
 * unshare has landed, then pause indefinitely.  The parent writes our
 * uid_map/gid_map externally (uid_map can be written from outside the
 * userns once setgroups has been denied), opens /proc/<pid>/ns/user
 * to capture the userns_fd, then SIGTERMs us.
 *
 * The ready_fd is the write end of a pipe the parent reads to
 * synchronise on the unshare completing.  On unshare success we write
 * one byte and close the fd; on failure we close it without writing,
 * which lets the parent's read() return 0 and abort cleanly without
 * racing the proc-file writes against the child's original userns.
 */
static __attribute__((noreturn)) void carrier_child(int ready_fd)
{
	char ready = 1;
	ssize_t w;

	if (unshare(CLONE_NEWUSER) < 0) {
		close(ready_fd);
		_exit(0);
	}

	do {
		w = write(ready_fd, &ready, 1);
	} while (w < 0 && errno == EINTR);
	close(ready_fd);

	/* Pause until SIGTERM.  pause() returns -1/EINTR on any
	 * signal; an unexpected EINTR (SIGALRM bleed-through from
	 * the trinity outer alarm) just loops back. */
	for (;;)
		(void)pause();
}

/*
 * Read the one-byte ready handshake from the carrier child, retrying
 * on EINTR.  Returns 0 if the child reported a successful unshare,
 * -1 on any other outcome (child failed the unshare and closed the
 * pipe, child died before writing, read error).
 */
static int wait_carrier_ready(int ready_fd)
{
	char b = 0;
	ssize_t r;

	do {
		r = read(ready_fd, &b, 1);
	} while (r < 0 && errno == EINTR);

	if (r != 1 || b != 1)
		return -1;
	return 0;
}

/*
 * Write a single line into /proc/<pid>/<file>.  open+write+close;
 * uid_map / gid_map / setgroups all take a single short write.
 * Returns 0 on success, -1 on failure (caller treats as latch /
 * skip).
 */
static int write_proc_file(pid_t pid, const char *file, const char *content)
{
	char path[64];
	int fd;
	ssize_t need, w;

	(void)snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, file);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	need = (ssize_t)strlen(content);
	w = write(fd, content, (size_t)need);
	close(fd);
	if (w != need)
		return -1;
	return 0;
}

/*
 * Build a carrier userns and return a file descriptor pinning it.
 * Returns -1 on any setup failure; the caller treats failure as
 * iteration-skip (not a latch -- a transient fork/setgroups failure
 * shouldn't kill the op for the rest of the child's life).
 */
static int build_carrier_userns(void)
{
	pid_t pid;
	int ns_fd = -1;
	int ready_pipe[2] = { -1, -1 };
	char nspath[64];
	char mapline[64];
	uid_t uid = geteuid();
	gid_t gid = getegid();
	int status;

	if (pipe2(ready_pipe, O_CLOEXEC) < 0) {
		__atomic_add_fetch(
			&shm->stats.statmount_idmap_carrier_fail,
			1, __ATOMIC_RELAXED);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		close(ready_pipe[0]);
		close(ready_pipe[1]);
		__atomic_add_fetch(
			&shm->stats.statmount_idmap_fork_failed,
			1, __ATOMIC_RELAXED);
		return -1;
	}
	if (pid == 0) {
		close(ready_pipe[0]);
		carrier_child(ready_pipe[1]);
	}

	/* Wait for the carrier to confirm unshare(CLONE_NEWUSER) has
	 * landed before touching /proc/<pid>/{setgroups,uid_map,gid_map}.
	 * Without this barrier the parent can race the child and write
	 * the proc files against the carrier's original user namespace,
	 * which fails and burns a fork per skipped iteration. */
	close(ready_pipe[1]);
	ready_pipe[1] = -1;
	if (wait_carrier_ready(ready_pipe[0]) < 0) {
		close(ready_pipe[0]);
		ready_pipe[0] = -1;
		goto fail;
	}
	close(ready_pipe[0]);
	ready_pipe[0] = -1;

	/* Best-effort: deny setgroups so a single-line gid_map is
	 * accepted from outside the carrier.  Failure is benign --
	 * the gid_map write below will simply fail and we abort. */
	(void)write_proc_file(pid, "setgroups", "deny");

	(void)snprintf(mapline, sizeof(mapline), "0 %u 1\n",
		       (unsigned int)uid);
	if (write_proc_file(pid, "uid_map", mapline) < 0)
		goto fail;

	(void)snprintf(mapline, sizeof(mapline), "0 %u 1\n",
		       (unsigned int)gid);
	if (write_proc_file(pid, "gid_map", mapline) < 0)
		goto fail;

	(void)snprintf(nspath, sizeof(nspath), "/proc/%d/ns/user",
		       (int)pid);
	ns_fd = open(nspath, O_RDONLY | O_CLOEXEC);
	if (ns_fd < 0)
		goto fail;

	(void)kill(pid, SIGTERM);
	(void)waitpid_eintr(pid, &status, 0);
	__atomic_add_fetch(
		&shm->stats.statmount_idmap_carrier_ok,
		1, __ATOMIC_RELAXED);
	return ns_fd;

fail:
	if (ns_fd >= 0)
		close(ns_fd);
	(void)kill(pid, SIGKILL);
	(void)waitpid_eintr(pid, &status, 0);
	__atomic_add_fetch(
		&shm->stats.statmount_idmap_carrier_fail,
		1, __ATOMIC_RELAXED);
	return -1;
}

/*
 * Build a detached tmpfs mount via the new-mount-API and return its
 * mount fd.  Returns -1 on failure; the caller treats failure as
 * iteration-skip.
 */
static int build_detached_tmpfs(void)
{
	int fs_fd, mnt_fd;
	long rc;

	fs_fd = (int)sys_fsopen("tmpfs", 0);
	if (fs_fd < 0)
		return -1;

	rc = sys_fsconfig(fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	if (rc < 0) {
		close(fs_fd);
		return -1;
	}

	mnt_fd = (int)sys_fsmount(fs_fd, 0, 0);
	close(fs_fd);
	if (mnt_fd < 0)
		return -1;
	return mnt_fd;
}

/*
 * mount_setattr(MOUNT_ATTR_IDMAP, userns_fd) on a detached mount fd
 * with AT_EMPTY_PATH.  Returns 0 on success, -1 on failure.
 */
static int install_idmap(int mnt_fd, int userns_fd)
{
	struct mount_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.attr_set = MOUNT_ATTR_IDMAP;
	attr.userns_fd = (__u64)userns_fd;

	if (sys_mount_setattr(mnt_fd, "", AT_EMPTY_PATH, &attr,
			      sizeof(attr)) < 0)
		return -1;
	return 0;
}

/*
 * Issue one statmount(STATMOUNT_BY_FD, mask = MNT_BASIC | MNT_UIDMAP
 * | MNT_GIDMAP | SUPPORTED_MASK, buf, bufsize, ...).  Every result
 * is coverage; bumps a stat by classification but never fails the
 * outer iteration.  buf is heap-allocated to the max sweep size so
 * the kernel cannot OOB-write past our allocation even if a bufsize
 * is mis-honoured.
 */
static void issue_one_statmount(int mnt_fd, void *buf,
				unsigned long bufsize)
{
	struct mnt_id_req_v1 req;
	long rc;

	/*
	 * STATMOUNT_BY_FD carries the mount fd in the offset-4 union
	 * member (mnt_fd) and requires mnt_id and mnt_ns_id to be
	 * zero; the kernel rejects the request with -EINVAL otherwise
	 * and the idmap serialization path is never reached.
	 */
	memset(&req, 0, sizeof(req));
	req.size = sizeof(req);
	req.mnt_fd = (__u32)mnt_fd;
	req.param = STATMOUNT_MNT_BASIC | STATMOUNT_MNT_UIDMAP |
		    STATMOUNT_MNT_GIDMAP | STATMOUNT_SUPPORTED_MASK;

	__atomic_add_fetch(
		&shm->stats.statmount_idmap_statmount_call,
		1, __ATOMIC_RELAXED);

	rc = sys_statmount(&req, (struct statmount *)buf, bufsize,
			   STATMOUNT_BY_FD);
	if (rc == 0) {
		__atomic_add_fetch(
			&shm->stats.statmount_idmap_statmount_ok,
			1, __ATOMIC_RELAXED);
	} else if (errno == EOVERFLOW) {
		__atomic_add_fetch(
			&shm->stats.statmount_idmap_statmount_overflow,
			1, __ATOMIC_RELAXED);
	}
}

/*
 * One outer iteration: build a carrier userns, build a detached
 * tmpfs, install the idmap, sweep bufsizes, tear it all down.
 */
static void iter_one(int op_type, void *scratch_buf, unsigned long scratch_cap)
{
	int userns_fd, mnt_fd;
	size_t i;
	/* op_type is copied from shared memory (child->op_type via
	 * ctx->op_type) and can be scribbled by a sibling poisoned-arena
	 * write; bounds-check before indexing the NR_CHILD_OP_TYPES-sized
	 * stats arrays, same pattern the child.c dispatch loop uses. */
	const bool valid_op = ((int) op_type >= 0 &&
			       op_type < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.statmount_idmap_iter,
			   1, __ATOMIC_RELAXED);

	userns_fd = build_carrier_userns();
	if (userns_fd < 0)
		return;

	mnt_fd = build_detached_tmpfs();
	if (mnt_fd < 0) {
		close(userns_fd);
		return;
	}

	if (install_idmap(mnt_fd, userns_fd) < 0) {
		__atomic_add_fetch(
			&shm->stats.statmount_idmap_setattr_fail,
			1, __ATOMIC_RELAXED);
		close(mnt_fd);
		close(userns_fd);
		return;
	}
	__atomic_add_fetch(&shm->stats.statmount_idmap_setattr_ok,
			   1, __ATOMIC_RELAXED);

	/* Per-iter setup gate passed: carrier built, detached tmpfs built,
	 * idmap installed.  Bump setup_accepted before any statmount() call
	 * so the delta against data_path attributes any pre-syscall bail
	 * (none currently, but future early-returns before the sweep would
	 * land here). */
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop_setup_accepted[op_type],
				   1, __ATOMIC_RELAXED);

	/* About to enter the kernel-exercising bufsize sweep.  Bump once
	 * per iter (not per statmount call) so setup_accepted == data_path
	 * is the steady-state. */
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop_data_path[op_type],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < ARRAY_SIZE(statmount_idmap_bufsizes); i++) {
		unsigned long sz = statmount_idmap_bufsizes[i];

		if (sz > scratch_cap)
			sz = scratch_cap;
		issue_one_statmount(mnt_fd, scratch_buf, sz);
	}

	close(mnt_fd);
	close(userns_fd);
}

/*
 * Per-invocation context handed to the in-ns callback so it can drive
 * the outer bufsize-sweep loop with the caller's op_type, BUDGETED
 * iteration count, and pre-allocated scratch buffer.
 */
struct statmount_idmap_ctx {
	int op_type;
	unsigned int outer_iters;
	void *scratch_buf;
	unsigned long scratch_cap;
};

/*
 * Body that must run inside the (CLONE_NEWUSER | CLONE_NEWNS) namespace
 * stack.  Executed in a transient grandchild forked by
 * userns_run_in_ns(); the grandchild's userns + mount ns are torn down
 * on _exit() so the detached tmpfs mount, the carrier sibling fork, and
 * any namespace-scoped resources iter_one() allocated are reaped by the
 * kernel along with the namespace stack.  Return value is ignored by
 * the helper.
 */
static int statmount_idmap_loop_in_ns(void *arg)
{
	struct statmount_idmap_ctx *ctx = (struct statmount_idmap_ctx *)arg;
	struct timespec t_outer;
	unsigned int i;

	/* MS_PRIVATE on / so anything we mount cannot propagate even
	 * if the host's mount namespace had MS_SHARED propagation. */
	(void)trinity_raw_syscall(__NR_mount, NULL, "/", NULL,
				  MS_REC | MS_PRIVATE, NULL);

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	for (i = 0; i < ctx->outer_iters; i++) {
		if (budget_elapsed_ns(&t_outer,
				      STATMOUNT_IDMAP_WALL_CAP_NS))
			break;
		iter_one(ctx->op_type, ctx->scratch_buf, ctx->scratch_cap);
	}

	return 0;
}

#endif /* HAVE_STATMOUNT_IDMAP_SYSCALLS */

bool statmount_idmap_overflow(struct childdata *child)
{
	/* child->op_type lives in shared memory and can be scribbled by a
	 * sibling poisoned-arena write; snapshot once and bounds-check
	 * before indexing the NR_CHILD_OP_TYPES-sized stats arrays, same
	 * pattern the child.c dispatch loop uses. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.statmount_idmap_runs,
			   1, __ATOMIC_RELAXED);

#ifndef HAVE_STATMOUNT_IDMAP_SYSCALLS
	statmount_idmap_unsupported = true;
	if (valid_op)
		__atomic_store_n(&shm->stats.childop_latch_reason[op],
				 CHILDOP_LATCH_UNSUPPORTED,
				 __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.statmount_idmap_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
#else
	{
	struct statmount_idmap_ctx ctx;
	unsigned int outer_iters;
	void *scratch_buf;
	const unsigned long scratch_cap = 16384UL;
	int rc;

	if (statmount_idmap_unsupported ||
	    ns_unshare_failed_statmount_idmap) {
		__atomic_add_fetch(
			&shm->stats.statmount_idmap_setup_failed,
			1, __ATOMIC_RELAXED);
		return true;
	}

	if (!statmount_idmap_probed) {
		probe_statmount_idmap();
		if (statmount_idmap_unsupported) {
			if (valid_op)
				__atomic_store_n(
					&shm->stats.childop_latch_reason[op],
					CHILDOP_LATCH_UNSUPPORTED,
					__ATOMIC_RELAXED);
			__atomic_add_fetch(
				&shm->stats.statmount_idmap_setup_failed,
				1, __ATOMIC_RELAXED);
			return true;
		}
	}

	scratch_buf = malloc(scratch_cap);
	if (scratch_buf == NULL) {
		__atomic_add_fetch(
			&shm->stats.statmount_idmap_setup_failed,
			1, __ATOMIC_RELAXED);
		return true;
	}

	outer_iters = BUDGETED(CHILD_OP_STATMOUNT_IDMAP_OVERFLOW,
			       STATMOUNT_IDMAP_OUTER_BASE);
	if (outer_iters == 0U)
		outer_iters = 1U;
	if (outer_iters > STATMOUNT_IDMAP_OUTER_CAP)
		outer_iters = STATMOUNT_IDMAP_OUTER_CAP;

	ctx.op_type = child->op_type;
	ctx.outer_iters = outer_iters;
	ctx.scratch_buf = scratch_buf;
	ctx.scratch_cap = scratch_cap;

	rc = userns_run_in_ns(CLONE_NEWNS, statmount_idmap_loop_in_ns, &ctx);
	free(scratch_buf);

	if (rc == -EPERM) {
		ns_unshare_failed_statmount_idmap = true;
		if (valid_op)
			__atomic_store_n(
				&shm->stats.childop_latch_reason[op],
				CHILDOP_LATCH_NS_UNSUPPORTED,
				__ATOMIC_RELAXED);
		__atomic_add_fetch(
			&shm->stats.statmount_idmap_setup_failed,
			1, __ATOMIC_RELAXED);
	} else if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map
		 * write, secondary CLONE_NEWNS unshare).  Skip this
		 * invocation without latching -- the failure is not
		 * policy and may not recur on the next call. */
		__atomic_add_fetch(
			&shm->stats.statmount_idmap_setup_failed,
			1, __ATOMIC_RELAXED);
	}

	return true;
	}
#endif
}
