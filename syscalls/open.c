#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include "files.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

static unsigned long open_o_flags_base[] = {
	O_RDONLY, O_WRONLY, O_RDWR, O_CREAT,
};

static const unsigned long o_flags[] = {
	O_EXCL, O_NOCTTY, O_TRUNC, O_APPEND,
	O_NONBLOCK, O_SYNC, O_ASYNC, O_DIRECTORY,
	O_NOFOLLOW, O_CLOEXEC, O_DIRECT, O_NOATIME,
	O_PATH, O_DSYNC, O_LARGEFILE, O_TMPFILE,
};

/*
 * Choose a random number of file flags to OR into the mask.
 * also used in files.c:open_file()
 */
unsigned long get_o_flags(void)
{
	unsigned long mask;

	mask = set_rand_bitmask(ARRAY_SIZE(o_flags), o_flags);

	return mask;
}

static void sanitise_open(struct syscallrecord *rec)
{
	unsigned long flags;

	flags = get_o_flags();

	rec->a2 |= flags;

	if (rec->a2 & O_CREAT)
		rec->a3 = 0666;

	if (rec->a2 & O_TMPFILE)
		rec->a3 = 0666;
}

static void sanitise_openat(struct syscallrecord *rec)
{
	unsigned long flags;

	flags = get_o_flags();

	rec->a3 |= flags;

	if (rec->a3 & O_CREAT)
		rec->a4 = 0666;

	if (rec->a3 & O_TMPFILE)
		rec->a4 = 0666;
}

/*
 * Close fds returned by open-family syscalls.  These fds point at
 * random filesystem paths and are not part of the curated fd pool
 * (which has its own providers for /dev, /proc, /sys, testfiles).
 * Without this, every successful open/openat/openat2/creat leaks
 * an fd in the child, eventually exhausting the fd table.
 */
static void post_open(struct syscallrecord *rec)
{
	int fd = rec->retval;
	struct stat st;

	if (fd == -1)
		return;

	/*
	 * Oracle: a freshly opened fd must refer to a valid inode.  If fstat
	 * fails here the kernel handed us an fd that doesn't point at anything
	 * — a clear sign of fd-table corruption.
	 */
	if (fstat(fd, &st) != 0) {
		output(0, "fd oracle: open/openat returned fd %d but "
		       "fstat failed (errno %d)\n", fd, errno);
		__atomic_add_fetch(&shm->stats.fd_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	close(fd);
}

/*
 * SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, int, mode)
 */
struct syscallentry syscall_open = {
	.name = "open",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_OP, [2] = ARG_MODE_T },
	.argname = { [0] = "filename", [1] = "flags", [2] = "mode" },
	.arg_params[1].list = ARGLIST(open_o_flags_base),
	.rettype = RET_FD,
	.flags = NEED_ALARM,
	.sanitise = sanitise_open,
	.post = post_open,
	.group = GROUP_VFS,
};

/*
 * Oracle: openat(AT_FDCWD, path, O_PATH) must produce an fd whose inode
 * matches stat(path).  A mismatch means the kernel wired the fd to the wrong
 * file-struct — silent corruption that KASAN won't catch.  Skip when
 * O_NOFOLLOW is also set: symlink fds diverge from their stat targets and
 * would generate false positives.
 */
static void post_openat(struct syscallrecord *rec)
{
	int fd = rec->retval;
	const char *path = (const char *) rec->a2;
	unsigned long flags = rec->a3;
	struct stat st_fd, st_path;

	if (fd == -1)
		return;

	if (fstat(fd, &st_fd) != 0) {
		output(0, "fd oracle: openat returned fd %d but "
		       "fstat failed (errno %d)\n", fd, errno);
		__atomic_add_fetch(&shm->stats.fd_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
		close(fd);
		return;
	}

	if ((flags & O_PATH) && !(flags & O_NOFOLLOW) &&
	    (int) rec->a1 == AT_FDCWD && path != NULL) {
		if (stat(path, &st_path) == 0 &&
		    (st_fd.st_dev != st_path.st_dev ||
		     st_fd.st_ino != st_path.st_ino)) {
			output(0, "fd oracle: openat(%s, O_PATH) inode mismatch "
			       "fd=(%lu:%lu) path=(%lu:%lu)\n",
			       path,
			       (unsigned long) st_fd.st_dev,
			       (unsigned long) st_fd.st_ino,
			       (unsigned long) st_path.st_dev,
			       (unsigned long) st_path.st_ino);
			__atomic_add_fetch(&shm->stats.fd_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}

	close(fd);
}

/*
 * SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags, int, mode)
 */
struct syscallentry syscall_openat = {
	.name = "openat",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_OP, [3] = ARG_MODE_T },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "flags", [3] = "mode" },
	.arg_params[2].list = ARGLIST(open_o_flags_base),
	.rettype = RET_FD,
	.flags = NEED_ALARM,
	.sanitise = sanitise_openat,
	.post = post_openat,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE4(openat2, int, dfd, const char __user *, filename,
                 struct open_how __user *, how, size_t, usize)
 */
#ifndef RESOLVE_NO_XDEV
struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};
#define RESOLVE_NO_XDEV		0x01
#define RESOLVE_NO_MAGICLINKS	0x02
#define RESOLVE_NO_SYMLINKS	0x04
#define RESOLVE_BENEATH		0x08
#define RESOLVE_IN_ROOT		0x10
#define RESOLVE_CACHED		0x20
#endif

static unsigned long openat2_resolve_flags[] = {
	RESOLVE_NO_XDEV, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS,
	RESOLVE_BENEATH, RESOLVE_IN_ROOT, RESOLVE_CACHED,
};

static void sanitise_openat2(struct syscallrecord *rec)
{
	struct open_how *how;

	how = zmalloc(sizeof(struct open_how));
	how->flags = RAND_ARRAY(open_o_flags_base) | get_o_flags();
	if (how->flags & (O_CREAT | O_TMPFILE))
		how->mode = 0666;
	how->resolve = set_rand_bitmask(ARRAY_SIZE(openat2_resolve_flags),
					openat2_resolve_flags);

	rec->a3 = (unsigned long) how;
	rec->a4 = sizeof(struct open_how);
	/* Snapshot for the post handler -- a3 may be scribbled by a sibling
	 * syscall before post_openat2() runs. */
	rec->post_state = (unsigned long) how;
}

static void post_openat2(struct syscallrecord *rec)
{
	void *how = (void *) rec->post_state;
	int fd = rec->retval;

	if (fd != -1)
		close(fd);

	if (how == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, how)) {
		outputerr("post_openat2: rejected suspicious how=%p (pid-scribbled?)\n", how);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a3 = 0;
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_openat2 = {
	.name = "openat2",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [3] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "how", [3] = "usize" },
	.rettype = RET_FD,
	.flags = NEED_ALARM,
	.sanitise = sanitise_openat2,
	.post = post_openat2,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(open_by_handle_at, int, mountdirfd,
 *               struct file_handle __user *, handle,
 *               int, flags)
 */
struct syscallentry syscall_open_by_handle_at = {
	.name = "open_by_handle_at",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_OP },
	.argname = { [0] = "mountdirfd", [1] = "handle", [2] = "flags" },
	.arg_params[2].list = ARGLIST(open_o_flags_base),
	.rettype = RET_FD,
	.flags = NEED_ALARM,
	.sanitise = sanitise_openat,	// For now we only sanitise .flags, which is also arg3
	.post = post_open,
	.group = GROUP_VFS,
};
