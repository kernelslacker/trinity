/*
 * fs_lifecycle: full filesystem mount→use→umount lifecycle sequences.
 *
 * Trinity already exercises individual VFS syscalls through the random
 * fuzzer, but superblock teardown, orphan inode handling, quota
 * accounting on unmount, and overlay copy-up all require a real
 * filesystem to be live across the full mount→use→umount cycle.  These
 * code paths are a persistent source of upstream CI bugs precisely because
 * they're unreachable through isolated syscall fuzzing.
 *
 * Each call to fs_lifecycle() picks one of six variants and runs it
 * inside a transient grandchild forked by userns_run_in_ns(), which
 * installs an identity-mapped CLONE_NEWUSER and a fresh CLONE_NEWNS.
 * The grandchild holds CAP_SYS_ADMIN scoped to its own userns -- the
 * persistent fuzz child's credentials are unchanged.  When the
 * callback returns the grandchild _exit()s and the namespace stack
 * (plus any leftover mounts) is torn down by the kernel along with
 * the process.
 *
 * Latch policy: userns_run_in_ns() returning -EPERM means the kernel
 * refused CLONE_NEWUSER (user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  That's a policy denial that
 * will not change for the life of this child, so ns_unsupported is
 * latched and every subsequent invocation short-circuits.  A return
 * of -EAGAIN (transient grandchild setup failure -- fork, id-map
 * write, secondary CLONE_NEWNS) is treated as a per-invocation skip
 * with no latch.  Per-fstype ENODEV inside a variant (CONFIG_RAMFS
 * or CONFIG_OVERLAY_FS off) is also a non-latching skip -- only the
 * helper -EPERM flips ns_unsupported.
 *
 * Variants:
 *   TMPFS   — fallocate/punch-hole, xattr, cross-dir rename,
 *             copy_file_range, sendfile, statx, then clean unmount
 *   RAMFS   — no swap, no writeback, no size limit; exercises the
 *             ramfs address_space_operations distinct from tmpfs
 *   RDONLY  — proc or sysfs mounted read-only in the private ns,
 *             walked and unmounted; hits pseudo-fs ->kill_sb paths
 *   OVERLAY — overlayfs over a tmpfs backing store: copy-up on write,
 *             whiteout on delete, two-stage unmount
 *   QUOTA   — tmpfs with size= cap; write past the limit to reach
 *             the ENOSPC path in shmem memory accounting
 *   BIND    — bind-mount a live tmpfs to a second path, then unmount
 *             the bind before the original to hit mntget/mntput paths
 */

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/mount.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>

#ifdef __linux__
#include <linux/falloc.h>
#include <linux/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#endif

#include "child.h"
#include "syscall-gate.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/fcntl.h"
#include "kernel/falloc.h"
#include "kernel/mount.h"
/* Latched per-child: kernel refused CLONE_NEWUSER (helper -EPERM) */
static bool ns_unsupported;

/* Per-child invocation counter: keeps directory names unique */
static unsigned int fslife_seq;

/*
 * Call statx via the raw syscall to avoid glibc version dependencies.
 */
#ifdef __NR_statx
static int do_statx(int dfd, const char *path, unsigned int flags,
		    unsigned int mask, struct statx *buf)
{
	return (int)trinity_raw_syscall(__NR_statx, dfd, path, flags, mask, buf);
}
#endif

/*
 * copy_file_range via syscall for the same reason.
 */
#ifdef __NR_copy_file_range
static ssize_t do_copy_file_range(int fd_in, off_t *off_in,
				  int fd_out, off_t *off_out,
				  size_t len, unsigned int flags)
{
	return (ssize_t)trinity_raw_syscall(__NR_copy_file_range,
				fd_in, off_in, fd_out, off_out, len, flags);
}
#endif

static void make_base_path(char *buf, size_t len)
{
	snprintf(buf, len, "%s/trinity-fslife-%d-%u",
		 trinity_tmpdir_abs(), (int)mypid(), fslife_seq++);
}

/*
 * Open path for writing (creating it), fill with sz bytes of fill, and
 * return the open fd.  Returns -1 on failure; caller must close on success.
 */
static int create_filled_file(const char *path, unsigned char fill, size_t sz)
{
	char buf[4096];
	size_t written = 0;
	ssize_t r;
	int fd;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -1;

	memset(buf, fill, sizeof(buf));
	while (written < sz) {
		size_t chunk = sz - written;
		if (chunk > sizeof(buf))
			chunk = sizeof(buf);
		r = write(fd, buf, chunk);
		if (r <= 0)
			break;
		written += (size_t)r;
	}
	return fd;
}

/* ------------------------------------------------------------------ */

/*
 * Variant 0: tmpfs full lifecycle.
 *
 * Exercises: superblock alloc/free, extent allocation (fallocate),
 * hole-punch, user xattr path, cross-directory rename (dcache move),
 * copy_file_range (in-kernel copy path), sendfile (splice), statx.
 */
static void do_tmpfs_lifecycle(void)
{
	char base[PATH_MAX + 64];
	char dira[PATH_MAX + 96], dirb[PATH_MAX + 96];
	char filea[PATH_MAX + 128], fileb[PATH_MAX + 128];
	char filec[PATH_MAX + 128], moved[PATH_MAX + 128];
	int fd_a = -1, fd_b = -1, fd_c = -1;
	bool mounted = false;

	make_base_path(base, sizeof(base));
	if (mkdir(base, 0755) != 0)
		return;

	if (mount("tmpfs", base, "tmpfs", 0, NULL) != 0)
		goto out_rmdir;
	mounted = true;

	snprintf(dira,  sizeof(dira),  "%s/a",       base);
	snprintf(dirb,  sizeof(dirb),  "%s/b",       base);
	snprintf(filea, sizeof(filea), "%s/a/src",   base);
	snprintf(fileb, sizeof(fileb), "%s/a/aux",   base);
	snprintf(filec, sizeof(filec), "%s/b/dst",   base);
	snprintf(moved, sizeof(moved), "%s/b/moved", base);

	mkdir(dira, 0755);
	mkdir(dirb, 0755);

	fd_a = create_filled_file(filea, 0xAB, 65536);
	if (fd_a < 0)
		goto cleanup;

	(void)fallocate(fd_a, 0, 0, 131072);
	(void)fallocate(fd_a, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
			4096, 4096);

	(void)fsetxattr(fd_a, "user.trinity", "fslife", 6, 0);
	{
		char xbuf[64];
		char lbuf[256];
		(void)fgetxattr(fd_a, "user.trinity", xbuf, sizeof(xbuf));
		(void)flistxattr(fd_a, lbuf, sizeof(lbuf));
		(void)fremovexattr(fd_a, "user.trinity");
	}

	fd_b = create_filled_file(fileb, 0xCD, 8192);
	if (fd_b < 0)
		goto cleanup;

	fd_c = open(filec, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd_c >= 0) {
#ifdef __NR_copy_file_range
		off_t off_in = 0, off_out = 0;
		(void)do_copy_file_range(fd_b, &off_in, fd_c, &off_out, 4096,
					 (unsigned int)RAND_NEGATIVE_OR(0));
#endif
		{
			off_t off = 0;
			(void)lseek(fd_b, 0, SEEK_SET);
			(void)sendfile(fd_c, fd_b, &off, 4096);
		}
#if defined(__NR_statx) && defined(STATX_BASIC_STATS)
		{
			struct statx stx;
			(void)do_statx(fd_c, "", AT_EMPTY_PATH,
				       STATX_BASIC_STATS, &stx);
		}
#endif
	}

	(void)rename(filea, moved);

cleanup:
	if (fd_a >= 0) close(fd_a);
	if (fd_b >= 0) close(fd_b);
	if (fd_c >= 0) close(fd_c);

	if (mounted)
		(void)umount2(base, MNT_DETACH);
out_rmdir:
	(void)rmdir(base);

	__atomic_add_fetch(&shm->stats.fs_lifecycle.tmpfs, 1, __ATOMIC_RELAXED);
}

/*
 * Variant 1: ramfs lifecycle.
 *
 * ramfs pages are never reclaimed or swapped; the address_space_operations
 * and super_operations differ from tmpfs.  Hard links and truncate→rewrite
 * exercise the paths that tmpfs punts to the swap layer.
 */
static void do_ramfs_lifecycle(void)
{
	char base[PATH_MAX + 64], subdir[PATH_MAX + 96];
	char filea[PATH_MAX + 128], fileb[PATH_MAX + 128];
	char linkpath[PATH_MAX + 128];
	int fd_a = -1, fd_b = -1;
	bool mounted = false;

	make_base_path(base, sizeof(base));
	if (mkdir(base, 0755) != 0)
		return;

	if (mount("ramfs", base, "ramfs", 0, NULL) != 0)
		goto out_rmdir;
	mounted = true;

	snprintf(subdir,   sizeof(subdir),   "%s/sub",      base);
	snprintf(filea,    sizeof(filea),    "%s/sub/file",  base);
	snprintf(fileb,    sizeof(fileb),    "%s/sub/ren",   base);
	snprintf(linkpath, sizeof(linkpath), "%s/sub/link",  base);

	mkdir(subdir, 0755);

	fd_a = create_filled_file(filea, 0x5A, 32768);
	if (fd_a < 0)
		goto cleanup;

	(void)fsetxattr(fd_a, "user.ramfs", "1", 1, 0);
	(void)fremovexattr(fd_a, "user.ramfs");

	fd_b = create_filled_file(fileb, 0xA5, 4096);
	if (fd_b >= 0) {
		int r __unused__;
		r = link(fileb, linkpath);
		(void)unlink(linkpath);
	}

	/* Truncate to zero then write again — new page allocated from ramfs. */
	{
		int r __unused__;
		r = ftruncate(fd_a, 0);
	}
	{
		const char msg[] = "ramfs-post-trunc";
		ssize_t n __unused__;
		n = write(fd_a, msg, sizeof(msg) - 1);
	}

cleanup:
	if (fd_a >= 0) close(fd_a);
	if (fd_b >= 0) close(fd_b);

	if (mounted)
		(void)umount2(base, MNT_DETACH);
out_rmdir:
	(void)rmdir(base);

	__atomic_add_fetch(&shm->stats.fs_lifecycle.ramfs, 1, __ATOMIC_RELAXED);
}

/*
 * Variant 2: read-only proc/sysfs traversal in a private mount.
 *
 * Mount a fresh proc or sysfs instance at a temp path, open and read
 * a handful of well-known entries, then unmount.  Exercises the
 * pseudo-filesystem ->kill_sb and ->put_super paths that differ from
 * tmpfs/ramfs.
 */
static void do_rdonly_lifecycle(void)
{
	static const struct {
		const char *fstype;
		const char *probe;
	} targets[] = {
		{ "proc",  "meminfo" },
		{ "sysfs", "block"   },
	};
	const char *fstype, *probe;
	char base[PATH_MAX + 64], probepath[PATH_MAX + 128];
	bool mounted = false;
	struct stat st;
	unsigned int idx;

	idx = rnd_modulo_u32(ARRAY_SIZE(targets));
	fstype = targets[idx].fstype;
	probe  = targets[idx].probe;

	make_base_path(base, sizeof(base));
	if (mkdir(base, 0755) != 0)
		return;

	if (mount(fstype, base, fstype, MS_RDONLY, NULL) != 0)
		goto out_rmdir;
	mounted = true;

	snprintf(probepath, sizeof(probepath), "%s/%s", base, probe);
	(void)stat(probepath, &st);

	{
		int fd = open(probepath, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd >= 0) {
			char buf[256];
			ssize_t n __unused__;
			n = read(fd, buf, sizeof(buf));
			close(fd);
		}
	}

	if (mounted)
		(void)umount2(base, MNT_DETACH);
out_rmdir:
	(void)rmdir(base);

	__atomic_add_fetch(&shm->stats.fs_lifecycle.rdonly, 1, __ATOMIC_RELAXED);
}

/*
 * Variant 3: overlayfs lifecycle.
 *
 * Build a three-layer overlayfs (lower/upper/work all on a tmpfs backing
 * store), then write through the merged view to trigger copy-up, delete
 * an existing file to generate a whiteout, and unmount both layers.
 * Copy-up and whiteout have historically been the densest sources of
 * overlayfs bugs.
 */
static void do_overlay_lifecycle(void)
{
	char base[PATH_MAX + 64];
	char lower[PATH_MAX + 96], upper[PATH_MAX + 96];
	char work[PATH_MAX + 96], merged[PATH_MAX + 96];
	char opt[3 * (PATH_MAX + 96) + 64];
	char lfile[PATH_MAX + 128], mfile[PATH_MAX + 128];
	int fd = -1;
	bool base_mounted = false, overlay_mounted = false;

	make_base_path(base, sizeof(base));
	if (mkdir(base, 0755) != 0)
		return;

	if (mount("tmpfs", base, "tmpfs", 0, NULL) != 0)
		goto out_rmdir;
	base_mounted = true;

	snprintf(lower,  sizeof(lower),  "%s/lower",  base);
	snprintf(upper,  sizeof(upper),  "%s/upper",  base);
	snprintf(work,   sizeof(work),   "%s/work",   base);
	snprintf(merged, sizeof(merged), "%s/merged", base);

	mkdir(lower, 0755);
	mkdir(upper, 0755);
	mkdir(work,  0755);
	mkdir(merged, 0755);

	snprintf(lfile, sizeof(lfile), "%s/shared", lower);
	fd = create_filled_file(lfile, 0x42, 4096);
	if (fd >= 0) close(fd);

	snprintf(opt, sizeof(opt),
		 "lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work);

	if (mount("overlay", merged, "overlay", 0, opt) != 0)
		goto cleanup_base;
	overlay_mounted = true;

	/* Write via merged → triggers copy-up of shared into upper. */
	snprintf(mfile, sizeof(mfile), "%s/shared", merged);
	fd = open(mfile, O_RDWR | O_CLOEXEC);
	if (fd >= 0) {
		const char msg[] = "overlay-upper-write";
		ssize_t n __unused__;
		n = write(fd, msg, sizeof(msg) - 1);
		close(fd);
	}

	/* New file created directly in upper via merged. */
	snprintf(mfile, sizeof(mfile), "%s/upper-only", merged);
	fd = create_filled_file(mfile, 0x99, 2048);
	if (fd >= 0)
		close(fd);

	/* Delete shared via merged → whiteout entry in upper. */
	snprintf(mfile, sizeof(mfile), "%s/shared", merged);
	(void)unlink(mfile);

	if (overlay_mounted)
		(void)umount2(merged, MNT_DETACH);
cleanup_base:
	if (base_mounted)
		(void)umount2(base, MNT_DETACH);
out_rmdir:
	(void)rmdir(base);

	__atomic_add_fetch(&shm->stats.fs_lifecycle.overlay, 1, __ATOMIC_RELAXED);
}

/*
 * Variant 4: tmpfs with size= quota limit.
 *
 * The size= mount option activates tmpfs memory accounting via
 * shmem_charge() / shmem_uncharge().  Writing past the cap returns
 * ENOSPC through a code path not reachable from a non-size-limited
 * tmpfs mount.
 */
static void do_quota_lifecycle(void)
{
	char base[PATH_MAX + 64], fpath[PATH_MAX + 128];
	int fd = -1;
	bool mounted = false;

	make_base_path(base, sizeof(base));
	if (mkdir(base, 0755) != 0)
		return;

	if (mount("tmpfs", base, "tmpfs", 0, "size=512k") != 0)
		goto out_rmdir;
	mounted = true;

	snprintf(fpath, sizeof(fpath), "%s/bigfile", base);
	fd = open(fpath, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		goto cleanup;

	{
		char buf[65536];
		ssize_t n __unused__;
		int i;
		memset(buf, 0xBB, sizeof(buf));
		/* Fill up to the 512k limit. */
		for (i = 0; i < 8; i++) {
			n = write(fd, buf, sizeof(buf));
		}
		/* One more write to hit ENOSPC. */
		n = write(fd, buf, sizeof(buf));
	}

cleanup:
	if (fd >= 0) close(fd);

	if (mounted)
		(void)umount2(base, MNT_DETACH);
out_rmdir:
	(void)rmdir(base);

	__atomic_add_fetch(&shm->stats.fs_lifecycle.quota, 1, __ATOMIC_RELAXED);
}

/*
 * Variant 5: bind-mount sequence.
 *
 * Mount a tmpfs, bind-mount it to a second path, access files via the
 * bind, unmount the bind, then unmount the original.  Two-step teardown
 * exercises attach_recursive_mnt() and the mntget/mntput reference
 * counting that guards against premature superblock release.
 */
static void do_bind_lifecycle(void)
{
	char src[PATH_MAX + 64], dst[PATH_MAX + 96], fpath[PATH_MAX + 128];
	int fd = -1;
	bool src_mounted = false, dst_mounted = false;

	make_base_path(src, sizeof(src));
	snprintf(dst, sizeof(dst), "%s-bnd", src);

	if (mkdir(src, 0755) != 0)
		return;
	if (mkdir(dst, 0755) != 0) {
		rmdir(src);
		return;
	}

	if (mount("tmpfs", src, "tmpfs", 0, NULL) != 0)
		goto out_rmdir;
	src_mounted = true;

	snprintf(fpath, sizeof(fpath), "%s/testfile", src);
	fd = create_filled_file(fpath, 0x77, 4096);
	if (fd >= 0) close(fd);

	if (mount(src, dst, NULL, MS_BIND, NULL) != 0)
		goto cleanup_src;
	dst_mounted = true;

	/* File visible via the bind path. */
	snprintf(fpath, sizeof(fpath), "%s/testfile", dst);
	fd = open(fpath, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		char buf[512];
		ssize_t n __unused__;
		n = read(fd, buf, sizeof(buf));
		close(fd);
	}

	/* Unmount bind before original — exercises the two-phase teardown. */
	if (dst_mounted)
		(void)umount2(dst, MNT_DETACH);
cleanup_src:
	if (src_mounted)
		(void)umount2(src, MNT_DETACH);
out_rmdir:
	(void)rmdir(dst);
	(void)rmdir(src);

	__atomic_add_fetch(&shm->stats.fs_lifecycle.bind, 1, __ATOMIC_RELAXED);
}

/* ------------------------------------------------------------------ */

/*
 * Per-invocation context handed to the in-ns callback.  Only the
 * variant index needs to cross the fork boundary -- everything else
 * the variants reach for (shm stats counters, tmpdir path) is either
 * shared-memory or world-readable and survives the namespace change.
 */
struct fs_lifecycle_ctx {
	unsigned int variant;
};

/*
 * Body that must run inside the (CLONE_NEWUSER | CLONE_NEWNS) namespace
 * stack.  Executed in a transient grandchild forked by
 * userns_run_in_ns(); the grandchild's userns + mount ns are torn down
 * on _exit() so any tmpfs/ramfs/overlay/bind mounts the variant set up
 * are reaped by the kernel along with the namespace stack.  Return
 * value is ignored by the helper.
 */
static int fs_lifecycle_in_ns(void *arg)
{
	struct fs_lifecycle_ctx *ctx = (struct fs_lifecycle_ctx *)arg;

	/* MS_PRIVATE on / so anything we mount cannot propagate even
	 * if the host's mount namespace had MS_SHARED propagation. */
	(void)mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);

	switch (ctx->variant) {
	case 0: do_tmpfs_lifecycle();   break;
	case 1: do_ramfs_lifecycle();   break;
	case 2: do_rdonly_lifecycle();  break;
	case 3: do_overlay_lifecycle(); break;
	case 4: do_quota_lifecycle();   break;
	case 5: do_bind_lifecycle();    break;
	}

	return 0;
}

bool fs_lifecycle(struct childdata *child)
{
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	struct fs_lifecycle_ctx ctx;
	int rc;

	if (ns_unsupported)
		return true;

	ctx.variant = rnd_modulo_u32(6);

	rc = userns_run_in_ns(CLONE_NEWNS, fs_lifecycle_in_ns, &ctx);

	if (rc == -EPERM) {
		/* CLONE_NEWUSER refused by kernel policy
		 * (user.max_user_namespaces=0 or
		 * kernel.unprivileged_userns_clone=0).  Latch and stop
		 * retrying for the lifetime of this trinity child. */
		ns_unsupported = true;
		__atomic_add_fetch(&shm->stats.fs_lifecycle.unsupported,
				   1, __ATOMIC_RELAXED);
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return true;
	}

	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary CLONE_NEWNS unshare).  Skip this invocation
		 * without latching -- the failure is not policy and may
		 * not recur on the next call. */
		return true;
	}

	/* rc == 0: the in-ns callback ran to completion.  Bump
	 * setup_accepted before data_path so the invariant
	 * data_path <= setup_accepted holds at every observation point;
	 * no bail path runs between the two bumps here. */
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	return true;
}
