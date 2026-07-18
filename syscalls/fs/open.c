#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include "csfu.h"
#include "files.h"
#include "pathnames.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so the pin lands
 * inside the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers (chmod, stat, utime, xattr-thrash, ...) touch.
 */
#define NR_TESTFILES 4

static unsigned long open_o_flags_base[] = {
	O_RDONLY, O_WRONLY, O_RDWR, O_CREAT,
};

#ifndef O_EMPTYPATH
#define O_EMPTYPATH 0x4000000
#endif

static const unsigned long o_flags[] = {
	O_EXCL, O_NOCTTY, O_TRUNC, O_APPEND,
	O_NONBLOCK, O_SYNC, O_ASYNC, O_DIRECTORY,
	O_NOFOLLOW, O_CLOEXEC, O_DIRECT, O_NOATIME,
	O_PATH, O_DSYNC, O_LARGEFILE, O_TMPFILE,
	O_EMPTYPATH,
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

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a2 and ARG_FD
	 * left a random dirfd in rec->a1, so the post_openat O_PATH
	 * inode-match oracle below (gated on a1 == AT_FDCWD and a
	 * stat()able path) is effectively dormant: the random dirfd
	 * almost never matches AT_FDCWD, and a stat() of the random
	 * pathname almost always ENOENTs before the oracle can compare
	 * inodes.
	 *
	 * Half the draws now repoint a2 at one of the trinity-testfile<N>
	 * absolute paths and AT_FDCWD-pin a1, so when get_o_flags() below
	 * happens to roll O_PATH the oracle has a real trinity-owned
	 * inode to compare against and can actually fire on a kernel
	 * file-struct/inode mismatch.  The other half preserves the
	 * random a1/a2 draw so the pre-existing random-path coverage --
	 * including the O_CREAT create-path on a random pathname -- stays
	 * exercised.
	 *
	 * openat with O_PATH is read-only on the inode, and a non-O_PATH
	 * open on an existing testfile only opens it (O_CREAT|O_EXCL
	 * EEXISTs, plain O_CREAT no-ops on an existing inode), so the
	 * pin cannot clobber the shared trinity-testfile pool that other
	 * read-only sanitisers depend on.
	 */
	if (rnd_modulo_u32(2) == 0) {
		char *path = get_testfile_path();

		if (path != NULL) {
			rec->a2 = (unsigned long) path;
			rec->a1 = (unsigned long) AT_FDCWD;
		}
	}

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

	if (fd < 0 || fd >= (1 << 20))
		return;

	/*
	 * Oracle: a freshly opened fd must refer to a valid inode.  If fstat
	 * fails here the kernel handed us an fd that doesn't point at anything
	 * — a clear sign of fd-table corruption.
	 */
	if (fstat(fd, &st) != 0) {
		output(0, "fd oracle: open/openat returned fd %d but "
		       "fstat failed (errno %d)\n", fd, errno);
		__atomic_add_fetch(&shm->stats.oracle.fd_oracle_anomalies, 1,
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

	if (fd < 0 || fd >= (1 << 20))
		return;

	if (fstat(fd, &st_fd) != 0) {
		output(0, "fd oracle: openat returned fd %d but "
		       "fstat failed (errno %d)\n", fd, errno);
		__atomic_add_fetch(&shm->stats.oracle.fd_oracle_anomalies, 1,
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
			__atomic_add_fetch(&shm->stats.oracle.fd_oracle_anomalies, 1,
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
#ifndef OPENAT2_REGULAR
#define OPENAT2_REGULAR		((__u64)1 << 32)
#endif

static unsigned long openat2_resolve_flags[] = {
	RESOLVE_NO_XDEV, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS,
	RESOLVE_BENEATH, RESOLVE_IN_ROOT, RESOLVE_CACHED,
};

/*
 * Curated RESOLVE_* combinations.  Random bitmask draws across the
 * RESOLVE_* set hit any individual combo with low probability, so the
 * sanitiser leans on a hand-picked table of unions that lookup_one_qstr
 * and the namei RESOLVE_* path actually branch on.  Includes the bare
 * single-flag entries, the RESOLVE_BENEATH / RESOLVE_IN_ROOT chroot-like
 * subsets, and a small set of multi-flag unions exercised by the
 * RESOLVE_NO_SYMLINKS + RESOLVE_NO_MAGICLINKS magic-link guard.  A 0
 * entry keeps the "default behaviour" path well-represented.
 */
static const unsigned long openat2_resolve_combos[] = {
	0,
	RESOLVE_NO_XDEV,
	RESOLVE_NO_MAGICLINKS,
	RESOLVE_NO_SYMLINKS,
	RESOLVE_BENEATH,
	RESOLVE_IN_ROOT,
	RESOLVE_CACHED,
	RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
	RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
	RESOLVE_BENEATH | RESOLVE_NO_XDEV,
	RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
	RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS,
	RESOLVE_IN_ROOT | RESOLVE_NO_XDEV,
	RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
	RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
};

static const struct csfu_desc desc_openat2 = {
	.name = "open_how",
	.ksize = sizeof(struct open_how),
};

/*
 * Legality-aware sanitiser for openat2(2).
 *
 * The kernel validates the open_how struct field-by-field via
 * copy_struct_from_user and build_open_flags:
 *
 *   - flags: open(2)-style.  __O_TMPFILE additionally requires
 *     O_DIRECTORY and one of O_WRONLY/O_RDWR; the O_TMPFILE uapi
 *     macro bundles the O_DIRECTORY bit already.
 *   - mode:  must be zero unless flags has O_CREAT or __O_TMPFILE
 *     (the kernel returns -EINVAL on a non-zero mode otherwise),
 *     and the supplied value is masked to S_IALLUGO.
 *   - resolve: bitmask of RESOLVE_* flags; any unknown bit set
 *     causes the kernel to return -EINVAL out of build_open_flags.
 *
 * The usize argument is independently validated against
 * sizeof(struct open_how) with copy_struct_from_user semantics;
 * the usize-vs-ksize bucket distribution lives in build_csfu_struct()
 * (see include/csfu.h) so every CSFU-shaped ABI gets uniform
 * coverage of the five buckets.
 *
 * Filling all three fields with legal-looking bytes and rolling
 * through the bucket distribution gets the syscall past the front-
 * door validators into the namei RESOLVE_* code paths and the
 * file-open machinery, which is where the interesting bugs live.
 */
static void sanitise_openat2(struct syscallrecord *rec)
{
	struct csfu_buf buf;
	struct open_how *how;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a2 and ARG_FD
	 * left a random dirfd in rec->a1, so RESOLVE_BENEATH / RESOLVE_IN_ROOT
	 * / O_PATH walks below almost always ENOENT in path lookup before the
	 * resolve-scope machinery ever runs.
	 *
	 * Half the draws now repoint a2 at one of the trinity-testfile<N>
	 * absolute paths and AT_FDCWD-pin a1, so the curated RESOLVE_* combos
	 * and the O_PATH / chroot-scope code paths get exercised against a
	 * real trinity-owned inode.  The other half preserves the random
	 * a1/a2 draw so the pre-existing random-path coverage stays exercised.
	 */
	if (rnd_modulo_u32(2) == 0) {
		char *path = get_testfile_path();

		if (path != NULL) {
			rec->a2 = (unsigned long) path;
			rec->a1 = (unsigned long) AT_FDCWD;
		}
	}

	buf = build_csfu_struct(&desc_openat2);
	how = buf.ptr;

	how->flags = RAND_ARRAY(open_o_flags_base) | get_o_flags();

	/*
	 * OPENAT2_REGULAR (upper-32-bit, openat2-exclusive) restricts the
	 * open to regular files; folded in on a fraction of draws so the
	 * S_ISREG gate arm gets covered without dominating the flag mix.
	 */
	if (ONE_IN(4))
		how->flags |= OPENAT2_REGULAR;

	/*
	 * mode is only legal when the kernel will create or materialise
	 * an inode (O_CREAT or __O_TMPFILE).  O_TMPFILE bundles
	 * O_DIRECTORY plus __O_TMPFILE, so a single mask check covers
	 * both.  Outside those, a non-zero mode trips the kernel's
	 * "mode set without O_CREAT/__O_TMPFILE" -EINVAL gate before
	 * any lookup work happens.
	 */
	if (how->flags & (O_CREAT | O_TMPFILE))
		how->mode = 0666;

	/*
	 * Resolve: ~25% draw an arbitrary subset of the RESOLVE_* set
	 * (covers unions the curated table omits); the rest pick from
	 * the curated combo table so the well-trodden RESOLVE_BENEATH
	 * and RESOLVE_IN_ROOT chroot-like paths get steady coverage.
	 */
	if (ONE_IN(4))
		how->resolve = set_rand_bitmask(ARRAY_SIZE(openat2_resolve_flags),
						openat2_resolve_flags);
	else
		how->resolve = RAND_ARRAY(openat2_resolve_combos);

	rec->a3 = (unsigned long) how;
	rec->a4 = buf.usize;

	/*
	 * a3 is ARG_ADDRESS, so the blanket address scrub in
	 * generate_syscall_args() would otherwise relocate the slot to a
	 * fresh writable-pool page without copying the curated open_how
	 * bytes, and the kernel would read a zeroed struct.  Move the
	 * buffer into the pool ourselves via the copy-preserving inout
	 * relocate so the bytes follow the pointer and the later blanket
	 * pass no-ops on the slot.  post_state still owns the original
	 * libc-heap how for cleanup_release_post_state to free.
	 */
	avoid_shared_buffer_inout(&rec->a3, buf.usize);

	/*
	 * Stash the csfu buffer in rec->post_state so the unconditional
	 * .cleanup hook frees it regardless of whether .post ran (when
	 * reject_corrupt_retfd() flags retfd, handle_syscall_ret() skips
	 * .post entirely).  post_state is private to the cleanup path and
	 * less stomp-prone than rec->a3, which post_openat2 zeros.
	 */
	rec->post_state = (unsigned long) how;
}

static void post_openat2(struct syscallrecord *rec)
{
	int fd = rec->retval;

	/*
	 * Bound the returned fd before close().  -1 is the documented
	 * failure return.  Any other out-of-range value is the fingerprint
	 * of a torn / sign-extended retval that would steer close() at a
	 * foreign fd in our own process; log + bump the corruption counter.
	 * Mirrors the bound used by post_open / post_openat / post_creat
	 * siblings.
	 */
	if (fd == -1) {
		rec->a3 = 0;
		return;
	}

	if (fd < 0 || fd >= (1 << 20)) {
		output(0, "post_openat2: rejected fd %d out of [0, 1<<20) before close\n", fd);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a3 = 0;
		return;
	}

	close(fd);
	rec->a3 = 0;
}

static void cleanup_openat2(struct syscallrecord *rec)
{
	cleanup_release_post_state(rec);
}

struct syscallentry syscall_openat2 = {
	.name = "openat2",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "how", [3] = "usize" },
	.rettype = RET_FD,
	.flags = NEED_ALARM,
	.sanitise = sanitise_openat2,
	.post = post_openat2,
	.cleanup = cleanup_openat2,
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
	.argtype = { [0] = ARG_FD, [1] = ARG_STRUCT_PTR_IN, [2] = ARG_OP },
	.argname = { [0] = "mountdirfd", [1] = "handle", [2] = "flags" },
	.arg_params[2].list = ARGLIST(open_o_flags_base),
	.rettype = RET_FD,
	.flags = NEED_ALARM,
	.sanitise = sanitise_openat,	// For now we only sanitise .flags, which is also arg3
	.post = post_open,
	.group = GROUP_VFS,
};
