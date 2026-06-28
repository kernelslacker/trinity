/*
 * scratch_block fd provider -- box-safety chokepoint for fuzzed block
 * I/O on top of the parent-side mount-namespace spine.
 *
 * Gates on shm->isolation.mnt_ready (the latch
 * setup_startup_isolation() raises after a successful unshare(CLONE_
 * NEWNS) + MS_REC|MS_PRIVATE remount of '/').  When live, opens
 * /dev/loop-control, calls LOOP_CTL_GET_FREE / LOOP_CONFIGURE over a
 * scratch image file of randomized power-of-two size, runs
 * `mkfs.ext4 -F -q <dev>` (best-effort: degrades to a loop-only entry
 * when mkfs.ext4 is absent or fails), and mounts the result under a
 * private subtree inside trinity's tmp/.  A tmpfs slot is added
 * unconditionally (default: tmpfs always; ext4 when both the
 * loop side and mkfs.ext4 succeed).
 *
 * The published entries in shm->isolation.scratch_block[] are the
 * ONLY block fds + device paths a child can draw.  Every loop number
 * came out of the kernel's own LOOP_CTL_GET_FREE allocation, so a
 * host disk node cannot enter the pool by construction; the
 * parent-held loop_fd keeps the binding alive across child
 * fuzz-closes; and the consuming childops gate at runtime on
 * scratch_block_ready + an entry with loop_num >= 0, falling back to
 * today's tmpfs/ramfs path when the pool is absent.
 *
 * Parent-teardown via atexit() (mirror self_cgroup_cleanup):
 * unmount + LOOP_CLR_FD on every published entry, close the
 * parent-held loop fd, unlink the backing image, rmdir the scratch
 * subtree.  Best-effort and idempotent throughout -- partial teardown
 * is harmless because the parent's private mount namespace is
 * destroyed with the process and the kernel auto-clears any lingering
 * loop binding on the last close.
 *
 * btrfs/xfs/vfat scratch entries are deferred (a follow-up); the
 * pool layout has SCRATCH_BLOCK_MAX headroom so adding them later
 * does not re-touch shm.
 */

#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "fd.h"
#include "objects.h"
#include "rnd.h"
#include "scratch_block.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#if __has_include(<linux/loop.h>)

#include <linux/loop.h>

/*
 * Backing-image size, picked uniformly from [SCRATCH_IMG_MIN_SHIFT,
 * SCRATCH_IMG_MAX_SHIFT].  Lower bound matches ext4's minimum useful
 * filesystem size (mkfs.ext4 rejects much smaller); upper bound keeps
 * the total host disk burn proportional even when the day-1 layout
 * grows toward SCRATCH_BLOCK_MAX entries.  Power-of-two so loop
 * device internal rounding is a no-op (blkdev-lifecycle-race.c relies
 * on the same shape to keep its per-iter window predictable).
 */
#define SCRATCH_IMG_MIN_SHIFT	22U		/* 4 MiB */
#define SCRATCH_IMG_MAX_SHIFT	25U		/* 32 MiB */

#define SCRATCH_ROOT_BASENAME	"scratch-block"

/*
 * Parent-only state for the atexit teardown.  Kept as file-scope
 * statics rather than in shm so child wild-writes cannot redirect
 * teardown into an attacker-chosen path (mirror self_cgroup.c's
 * cg_workload, cg_workload_fd handling).  The published view children
 * read lives in shm->isolation.scratch_block[].
 */
static char scratch_root_abs[PATH_MAX];
static int loopctl_fd = -1;
static bool scratch_block_atexit_armed;

/*
 * fork()/execlp() mkfs.ext4 -F -q against @dev_path.  Returns true on
 * a clean exit(0); false on missing binary, exec failure, signal, or
 * non-zero exit.  stdio is redirected to /dev/null so a chatty
 * mkfs.ext4 build cannot interleave with trinity's startup banner.
 *
 * Blocking waitpid: a small ext4 image formats in well under a second
 * and the parent is single-threaded at this point.  If mkfs.ext4
 * truly hangs the host is in a state where trinity cannot fuzz
 * usefully anyway.
 */
static bool run_mkfs_ext4(const char *dev_path)
{
	pid_t pid;
	pid_t got;
	int status;

	pid = fork();
	if (pid < 0)
		return false;

	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);

		if (devnull >= 0) {
			(void)dup2(devnull, STDIN_FILENO);
			(void)dup2(devnull, STDOUT_FILENO);
			(void)dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		execlp("mkfs.ext4", "mkfs.ext4", "-F", "-q",
		       dev_path, (char *)NULL);
		_exit(127);
	}

	do {
		got = waitpid(pid, &status, 0);
	} while (got < 0 && errno == EINTR);

	if (got < 0)
		return false;
	if (!WIFEXITED(status))
		return false;
	return WEXITSTATUS(status) == 0;
}

/*
 * mkdir(SCRATCH_ROOT_BASENAME) inside trinity's CWD (the tmp/ subdir
 * change_tmp_dir() left us in) and capture its absolute path so the
 * atexit teardown can re-resolve paths even if a child's fuzzed
 * chdir() raced.  Children never run cleanup, but defense-in-depth.
 */
static bool scratch_root_create(void)
{
	char cwd[PATH_MAX];

	if (mkdir(SCRATCH_ROOT_BASENAME, 0755) != 0 && errno != EEXIST)
		return false;
	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return false;
	if ((size_t)snprintf(scratch_root_abs, sizeof(scratch_root_abs),
			     "%s/%s", cwd, SCRATCH_ROOT_BASENAME) >=
	    sizeof(scratch_root_abs))
		return false;
	return true;
}

/*
 * Format an absolute path under the scratch root into @out (size @len).
 * Returns true on success, false if the path would exceed the
 * destination buffer (callers treat that as "skip this slot").
 */
static bool scratch_format_path(char *out, size_t len,
				const char *suffix_fmt,
				unsigned int idx)
{
	char suffix[64];
	int n;

	n = snprintf(suffix, sizeof(suffix), suffix_fmt, idx);
	if (n < 0 || (size_t)n >= sizeof(suffix))
		return false;
	n = snprintf(out, len, "%s/%s", scratch_root_abs, suffix);
	if (n < 0 || (size_t)n >= len)
		return false;
	return true;
}

/*
 * Best-effort tear-down of one published entry.  Used both by the
 * atexit chain and by the init-time partial-failure path.  The
 * caller's view of the entry stays addressable; this routine just
 * stamps the published fields back to "empty" so a subsequent reader
 * observes the slot as unused.
 */
static void scratch_entry_release(unsigned int idx)
{
	struct scratch_block_entry *e = &shm->isolation.scratch_block[idx];

	if (e->mount_path[0] != '\0') {
		/* MNT_DETACH so a still-busy mount unmounts asynchronously
		 * instead of failing the teardown chain. */
		(void)umount2(e->mount_path, MNT_DETACH);
		(void)rmdir(e->mount_path);
		e->mount_path[0] = '\0';
	}
	if (e->loop_fd >= 0) {
		(void)ioctl(e->loop_fd, LOOP_CLR_FD);
		close(e->loop_fd);
		e->loop_fd = -1;
	}
	if (e->loop_num >= 0) {
		char img_path[PATH_MAX];

		if (scratch_format_path(img_path, sizeof(img_path),
					"img%u", idx))
			(void)unlink(img_path);
		e->loop_num = -1;
	}
	e->dev_path[0] = '\0';
	e->fs_type[0] = '\0';
}

/*
 * Tear down every published entry (LIFO: leaves first, then trunk).
 * Idempotent against the partial-init path that already released a
 * slot.  No errors are surfaced -- atexit context, the kernel
 * destroys the mount namespace with the process and auto-clears
 * lingering loop bindings on the last fd close.
 */
static void scratch_block_atexit_cleanup(void)
{
	unsigned int i;

	if (!scratch_block_atexit_armed)
		return;

	for (i = 0; i < shm->isolation.scratch_block_count; i++)
		scratch_entry_release(i);

	if (loopctl_fd >= 0) {
		close(loopctl_fd);
		loopctl_fd = -1;
	}
	if (scratch_root_abs[0] != '\0')
		(void)rmdir(scratch_root_abs);

	__atomic_store_n(&shm->isolation.scratch_block_ready, false,
			 __ATOMIC_RELAXED);
	shm->isolation.scratch_block_count = 0;
}

/*
 * Allocate one ext4-on-loop scratch slot.  Steps:
 *   1. create + ftruncate the backing image to a random power-of-two
 *      size in [4 MiB, 32 MiB];
 *   2. LOOP_CTL_GET_FREE to reserve a fresh loop number;
 *   3. open /dev/loop$N and bind the image with LOOP_CONFIGURE
 *      (LOOP_SET_FD fallback for older kernels);
 *   4. close the backing fd -- the kernel holds its own reference
 *      until LOOP_CLR_FD;
 *   5. fork mkfs.ext4 -F -q; on failure publish a loop-only slot
 *      (no mount, fs_type = "none") so block-fd consumers still get
 *      a vetted /dev/loopN to fuzz;
 *   6. mount the loop dev as ext4 under the scratch subtree.
 *
 * Populates *out on success and any partial-loop-without-mount path.
 * Returns true if the parent now owns a loop fd it must tear down.
 */
static bool scratch_make_loop(unsigned int idx, struct scratch_block_entry *out)
{
	char img_path[PATH_MAX];
	char mount_path[PATH_MAX];
	char dev_path[32];
	int img_fd;
	int loop_fd;
	int loop_num;
	int n;
	off_t size;
	unsigned int shift;
	struct loop_config cfg;

	if (!scratch_format_path(img_path, sizeof(img_path), "img%u", idx))
		return false;
	if (!scratch_format_path(mount_path, sizeof(mount_path),
				 "mnt%u", idx))
		return false;

	(void)unlink(img_path);
	img_fd = open(img_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (img_fd < 0)
		return false;

	shift = SCRATCH_IMG_MIN_SHIFT +
		rnd_modulo_u32(SCRATCH_IMG_MAX_SHIFT -
			       SCRATCH_IMG_MIN_SHIFT + 1U);
	size = (off_t)1 << shift;
	if (ftruncate(img_fd, size) < 0) {
		close(img_fd);
		(void)unlink(img_path);
		return false;
	}

	loop_num = ioctl(loopctl_fd, LOOP_CTL_GET_FREE);
	if (loop_num < 0) {
		output(0, "scratch_block: LOOP_CTL_GET_FREE failed: %s\n",
		       strerror(errno));
		close(img_fd);
		(void)unlink(img_path);
		return false;
	}

	n = snprintf(dev_path, sizeof(dev_path), "/dev/loop%d", loop_num);
	if (n < 0 || (size_t)n >= sizeof(dev_path)) {
		close(img_fd);
		(void)unlink(img_path);
		return false;
	}

	loop_fd = open(dev_path, O_RDWR | O_CLOEXEC);
	if (loop_fd < 0) {
		output(0, "scratch_block: open(%s) failed: %s\n",
		       dev_path, strerror(errno));
		close(img_fd);
		(void)unlink(img_path);
		return false;
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.fd = (uint32_t)img_fd;
	if (ioctl(loop_fd, LOOP_CONFIGURE, &cfg) < 0) {
		/* LOOP_CONFIGURE landed in 5.8; LOOP_SET_FD has always
		 * worked.  Fall back so older kernels still get a pool. */
		if (ioctl(loop_fd, LOOP_SET_FD,
			  (unsigned long)img_fd) < 0) {
			output(0, "scratch_block: LOOP_CONFIGURE/LOOP_SET_FD on %s failed: %s\n",
			       dev_path, strerror(errno));
			close(loop_fd);
			close(img_fd);
			(void)unlink(img_path);
			return false;
		}
	}

	/* The kernel holds its own reference to the backing file via
	 * the loop struct; our img_fd is no longer needed and would
	 * just sit in the parent's fd table for the run's lifetime. */
	close(img_fd);

	/* Pre-populate the published entry with the loop-only shape so
	 * the box-safety contract holds even when the mkfs/mount steps
	 * below fall through. */
	out->loop_num = loop_num;
	out->loop_fd = loop_fd;
	memcpy(out->dev_path, dev_path, sizeof(out->dev_path));
	out->mount_path[0] = '\0';
	memcpy(out->fs_type, "none", 5);

	if (mkdir(mount_path, 0755) != 0 && errno != EEXIST)
		return true;

	if (!run_mkfs_ext4(dev_path)) {
		output(0, "scratch_block: mkfs.ext4 unavailable for %s; pool entry kept loop-only\n",
		       dev_path);
		(void)rmdir(mount_path);
		return true;
	}

	if (mount(dev_path, mount_path, "ext4", 0, NULL) != 0) {
		output(0, "scratch_block: mount(%s ext4 -> %s) failed: %s; pool entry kept loop-only\n",
		       dev_path, mount_path, strerror(errno));
		(void)rmdir(mount_path);
		return true;
	}

	n = snprintf(out->mount_path, sizeof(out->mount_path),
		     "%s", mount_path);
	if (n < 0 || (size_t)n >= (int)sizeof(out->mount_path)) {
		/* Cannot record the mount path -- unmount so atexit
		 * teardown doesn't leak a mount the published entry
		 * doesn't name. */
		(void)umount2(mount_path, MNT_DETACH);
		(void)rmdir(mount_path);
		out->mount_path[0] = '\0';
		return true;
	}
	memcpy(out->fs_type, "ext4", 5);
	return true;
}

/*
 * Add a tmpfs slot under the scratch subtree.  By default, tmpfs is
 * ALWAYS present even when the loop side fully degrades, so
 * mount-aware childops have a writable scratch fs to chase that does
 * not cross into block-device territory.  Sized small (16 MiB) so a
 * runaway fill from a fuzz syscall cannot eat host memory.
 */
static bool scratch_make_tmpfs(unsigned int idx, struct scratch_block_entry *out)
{
	char mount_path[PATH_MAX];
	int n;

	if (!scratch_format_path(mount_path, sizeof(mount_path),
				 "mnt%u", idx))
		return false;
	if (mkdir(mount_path, 0755) != 0 && errno != EEXIST)
		return false;
	if (mount("tmpfs", mount_path, "tmpfs", 0, "size=16M") != 0) {
		output(0, "scratch_block: tmpfs mount %s failed: %s\n",
		       mount_path, strerror(errno));
		(void)rmdir(mount_path);
		return false;
	}

	out->loop_num = -1;
	out->loop_fd = -1;
	out->dev_path[0] = '\0';
	n = snprintf(out->mount_path, sizeof(out->mount_path),
		     "%s", mount_path);
	if (n < 0 || (size_t)n >= (int)sizeof(out->mount_path)) {
		(void)umount2(mount_path, MNT_DETACH);
		(void)rmdir(mount_path);
		return false;
	}
	memcpy(out->fs_type, "tmpfs", 6);
	return true;
}

static void scratch_block_dump(struct object *obj, enum obj_scope scope)
{
	struct fileobj *fo = &obj->fileobj;

	output(2, "scratch_block fd:%d filename:%s scope:%d\n",
		fo->fd, fo->filename ? fo->filename : "?", scope);
}

/*
 * Publish a loop slot's fd into OBJ_FD_SCRATCH_BLOCK so the regular
 * fd_provider .get() callback finds it.  fileobj.filename points into
 * shm->isolation directly: that memory lives for the process lifetime
 * and is parent-write / child-read, matching the "stable strings"
 * convention dev_template uses for its compile-time table.  tmpfs
 * slots have no loop fd and are not published.
 */
static void scratch_publish_object(struct scratch_block_entry *e)
{
	struct object *obj;

	if (e->loop_fd < 0)
		return;

	obj = alloc_object();
	if (obj == NULL)
		return;

	obj->fileobj.fd = e->loop_fd;
	obj->fileobj.filename = e->dev_path;
	obj->fileobj.flags = O_RDWR;
	obj->fileobj.fopened = false;
	obj->fileobj.pagecache_backed = false;
	obj->fileobj.is_setuid = false;
	obj->fileobj.fcntl_flags = 0;
	obj->fileobj.obj_flags = 0;

	add_object(obj, OBJ_GLOBAL, OBJ_FD_SCRATCH_BLOCK);
}

static int init_scratch_block(void)
{
	struct objhead *head;
	unsigned int next = 0;
	unsigned int loop_published = 0;

	/* Box-safety gate: without the parent's private mount namespace,
	 * any mount() we issue lands in the host mount tree and any
	 * loop binding pollutes a host-visible device node.  Degrade
	 * silently -- childops that depended on the pool consult
	 * scratch_block_ready themselves and fall back to today's
	 * per-child tmpfs/ramfs path. */
	if (!__atomic_load_n(&shm->isolation.mnt_ready, __ATOMIC_RELAXED)) {
		fd_provider_init_fail(FD_INIT_REASON_CONFIG_ABSENT, 0,
				      "mnt_ready=0");
		return false;
	}

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SCRATCH_BLOCK);
	head->dump = &scratch_block_dump;

	if (!scratch_root_create()) {
		fd_provider_init_fail(FD_INIT_REASON_RESOURCE, errno,
				      "mkdir scratch root");
		return false;
	}

	/* /dev/loop-control is only needed for the ext4-on-loop slot;
	 * absence is tolerated so the pool can still publish tmpfs. */
	loopctl_fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (loopctl_fd < 0) {
		output(0, "scratch_block: open(/dev/loop-control) failed: %s -- loop slot skipped\n",
		       strerror(errno));
	} else if (next < SCRATCH_BLOCK_MAX) {
		struct scratch_block_entry *e =
			&shm->isolation.scratch_block[next];

		if (scratch_make_loop(next, e)) {
			scratch_publish_object(e);
			loop_published++;
			next++;
			shm->isolation.scratch_block_count = next;
		}
	}

	if (next < SCRATCH_BLOCK_MAX) {
		struct scratch_block_entry *e =
			&shm->isolation.scratch_block[next];

		if (scratch_make_tmpfs(next, e)) {
			next++;
			shm->isolation.scratch_block_count = next;
		}
	}

	if (shm->isolation.scratch_block_count == 0) {
		fd_provider_init_fail(FD_INIT_REASON_RESOURCE, 0,
				      "pool empty");
		if (loopctl_fd >= 0) {
			close(loopctl_fd);
			loopctl_fd = -1;
		}
		(void)rmdir(scratch_root_abs);
		scratch_root_abs[0] = '\0';
		return false;
	}

	/* Arm the atexit teardown only on success -- mirror
	 * self_cgroup_setup's contract that cleanup runs only when
	 * setup actually produced state to tear down.  atexit() is
	 * idempotent against a second call but we only need one. */
	if (!scratch_block_atexit_armed) {
		scratch_block_atexit_armed = true;
		atexit(scratch_block_atexit_cleanup);
	}

	__atomic_store_n(&shm->isolation.scratch_block_ready, true,
			 __ATOMIC_RELAXED);

	output(0, "scratch_block: pool ready (%u entries, %u loop) under %s\n",
	       shm->isolation.scratch_block_count, loop_published,
	       scratch_root_abs);

	return true;
}

/*
 * Random loop fd from the pool.  Matches the canary/dev_template
 * shape: bounded retry over a versioned slot pick to ride out an
 * objpool_check() failure (cold-recycle window for the OBJ_GLOBAL
 * lockless reader), and an explicit fd < 0 / EBADF guard so a
 * fuzz-induced close in a sibling child doesn't escape stale fd
 * numbers into a syscall arg.
 */
static int get_rand_scratch_block_fd(void)
{
	int i;

	if (objects_empty(OBJ_FD_SCRATCH_BLOCK) == true)
		return -1;

	for (i = 0; i < 100; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_SCRATCH_BLOCK, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_SCRATCH_BLOCK))
			continue;
		fd = obj->fileobj.fd;
		if (fd < 0)
			continue;
		if (fcntl(fd, F_GETFD) == -1)
			continue;
		return fd;
	}
	return -1;
}

static const struct fd_provider scratch_block_provider = {
	.name = "scratch_block",
	.objtype = OBJ_FD_SCRATCH_BLOCK,
	.enabled = true,
	.init = &init_scratch_block,
	.get = &get_rand_scratch_block_fd,
};

REG_FD_PROV(scratch_block_provider);

int scratch_block_random_loop_num(void)
{
	unsigned int count;
	unsigned int start;
	unsigned int i;

	if (!__atomic_load_n(&shm->isolation.scratch_block_ready,
			     __ATOMIC_RELAXED))
		return -1;
	count = shm->isolation.scratch_block_count;
	if (count == 0)
		return -1;

	start = rnd_modulo_u32(count);
	for (i = 0; i < count; i++) {
		struct scratch_block_entry *e =
			&shm->isolation.scratch_block[(start + i) % count];

		if (e->loop_num >= 0)
			return e->loop_num;
	}
	return -1;
}

#else  /* !__has_include(<linux/loop.h>) */

/*
 * No <linux/loop.h> in the build environment: register a stub
 * provider so the dispatcher's "registered but not enabled" logging
 * names the missing dependency, and return -1 from the helper.
 */
static int init_scratch_block(void)
{
	fd_provider_init_fail(FD_INIT_REASON_CONFIG_ABSENT, 0,
			      "<linux/loop.h> missing");
	return false;
}

static int get_rand_scratch_block_fd(void)
{
	return -1;
}

static const struct fd_provider scratch_block_provider = {
	.name = "scratch_block",
	.objtype = OBJ_FD_SCRATCH_BLOCK,
	.enabled = true,
	.init = &init_scratch_block,
	.get = &get_rand_scratch_block_fd,
};

REG_FD_PROV(scratch_block_provider);

int scratch_block_random_loop_num(void)
{
	return -1;
}

#endif /* __has_include(<linux/loop.h>) */
