/*
 * fs_lifecycle: full filesystem mount→use→umount lifecycle sequences.
 *
 * Trinity already exercises individual VFS syscalls through the random
 * fuzzer, but superblock teardown, orphan inode handling, quota
 * accounting on unmount, and overlay copy-up all require a real
 * filesystem to be live across the full mount→use→umount cycle.  These
 * code paths are a persistent source of syzbot bugs precisely because
 * they're unreachable through isolated syscall fuzzing.
 *
 * Each call to fs_lifecycle() picks one of six variants and runs it to
 * completion inside the child's private mount namespace.  The namespace
 * is obtained once via unshare(CLONE_NEWNS) on first entry and latched
 * for the life of the child process.  If the kernel denies the unshare
 * or the first mount() call returns EPERM, a per-process flag is set
 * and all subsequent invocations become no-ops.
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
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifdef __linux__
#include <linux/falloc.h>
#include <linux/stat.h>
#endif

#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE 0x01
#endif

#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE 0x02
#endif

/* Latched per-child: private mount namespace is in place */
static bool ns_unshared;
/* Latched per-child: namespace or first mount denied with EPERM */
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
	return (int)syscall(__NR_statx, dfd, path, flags, mask, buf);
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
	return (ssize_t)syscall(__NR_copy_file_range,
				fd_in, off_in, fd_out, off_out, len, flags);
}
#endif

static void make_base_path(char *buf, size_t len)
{
	snprintf(buf, len, "%s/trinity-fslife-%d-%u",
		 trinity_tmpdir_abs(), (int)getpid(), fslife_seq++);
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

/*
 * Ensure this child has a private mount namespace.  On first call the
 * namespace is created via unshare() and the root is made recursively
 * private so mounts cannot propagate back to the parent ns.  Subsequent
 * calls return immediately.
 */
static bool ensure_private_ns(void)
{
	if (ns_unshared)
		return true;
	if (ns_unsupported)
		return false;

	if (unshare(CLONE_NEWNS) != 0) {
		ns_unsupported = true;
		__atomic_add_fetch(&shm->stats.fs_lifecycle_unsupported,
				   1, __ATOMIC_RELAXED);
		return false;
	}

	if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
		ns_unsupported = true;
		__atomic_add_fetch(&shm->stats.fs_lifecycle_unsupported,
				   1, __ATOMIC_RELAXED);
		output(0, "fs_lifecycle: MS_PRIVATE remount failed (errno=%d), disabling\n",
		       errno);
		return false;
	}

	ns_unshared = true;
	return true;
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

	if (mount("tmpfs", base, "tmpfs", 0, NULL) != 0) {
		if (errno == EPERM) {
			ns_unsupported = true;
			__atomic_add_fetch(&shm->stats.fs_lifecycle_unsupported,
					   1, __ATOMIC_RELAXED);
		}
		goto out_rmdir;
	}
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
		(void)do_copy_file_range(fd_b, &off_in, fd_c, &off_out, 4096, 0);
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

	__atomic_add_fetch(&shm->stats.fs_lifecycle_tmpfs, 1, __ATOMIC_RELAXED);
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

	if (mount("ramfs", base, "ramfs", 0, NULL) != 0) {
		if (errno == EPERM)
			ns_unsupported = true;
		goto out_rmdir;
	}
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

	__atomic_add_fetch(&shm->stats.fs_lifecycle_ramfs, 1, __ATOMIC_RELAXED);
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

	idx = (unsigned int)rand() % ARRAY_SIZE(targets);
	fstype = targets[idx].fstype;
	probe  = targets[idx].probe;

	make_base_path(base, sizeof(base));
	if (mkdir(base, 0755) != 0)
		return;

	if (mount(fstype, base, fstype, MS_RDONLY, NULL) != 0) {
		if (errno == EPERM)
			ns_unsupported = true;
		goto out_rmdir;
	}
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

	__atomic_add_fetch(&shm->stats.fs_lifecycle_rdonly, 1, __ATOMIC_RELAXED);
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

	if (mount("tmpfs", base, "tmpfs", 0, NULL) != 0) {
		if (errno == EPERM)
			ns_unsupported = true;
		goto out_rmdir;
	}
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
	if (fd >= 0) { close(fd); fd = -1; }

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
		close(fd); fd = -1;
	}

	/* New file created directly in upper via merged. */
	snprintf(mfile, sizeof(mfile), "%s/upper-only", merged);
	fd = create_filled_file(mfile, 0x99, 2048);
	if (fd >= 0) { close(fd); fd = -1; }

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

	__atomic_add_fetch(&shm->stats.fs_lifecycle_overlay, 1, __ATOMIC_RELAXED);
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

	if (mount("tmpfs", base, "tmpfs", 0, "size=512k") != 0) {
		if (errno == EPERM)
			ns_unsupported = true;
		goto out_rmdir;
	}
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

	__atomic_add_fetch(&shm->stats.fs_lifecycle_tmpfs, 1, __ATOMIC_RELAXED);
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

	if (mount("tmpfs", src, "tmpfs", 0, NULL) != 0) {
		if (errno == EPERM)
			ns_unsupported = true;
		goto out_rmdir;
	}
	src_mounted = true;

	snprintf(fpath, sizeof(fpath), "%s/testfile", src);
	fd = create_filled_file(fpath, 0x77, 4096);
	if (fd >= 0) { close(fd); fd = -1; }

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
		close(fd); fd = -1;
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

	__atomic_add_fetch(&shm->stats.fs_lifecycle_tmpfs, 1, __ATOMIC_RELAXED);
}

/* ------------------------------------------------------------------ */

bool fs_lifecycle(struct childdata *child __unused__)
{
	if (!ensure_private_ns())
		return true;

	switch (rand() % 6) {
	case 0: do_tmpfs_lifecycle();   break;
	case 1: do_ramfs_lifecycle();   break;
	case 2: do_rdonly_lifecycle();  break;
	case 3: do_overlay_lifecycle(); break;
	case 4: do_quota_lifecycle();   break;
	case 5: do_bind_lifecycle();    break;
	}

	return true;
}
