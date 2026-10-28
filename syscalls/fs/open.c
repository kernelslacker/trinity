#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#include "csfu.h"
#include "ctime-rule.h"
#include "fd.h"
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

/*
 * Access-mode enum: exactly one of O_RDONLY/O_WRONLY/O_RDWR occupies the
 * low two bits of the flags word.  O_CREAT is an independent modifier and
 * is OR'd in separately by each sanitiser so the create-a-file-to-write-it
 * shapes (O_WRONLY|O_CREAT, O_RDWR|O_CREAT|O_EXCL, ...) are actually
 * reachable instead of colliding with the pick-one access-mode draw.
 */
static unsigned long open_o_flags_base[] = {
	O_RDONLY, O_WRONLY, O_RDWR,
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

	if (ONE_IN(4))
		rec->a2 |= O_CREAT;

	if (rec->a2 & O_CREAT)
		rec->a3 = 0666;

	if (rec->a2 & O_TMPFILE)
		rec->a3 = 0666;
}

/*
 * The directories a judged path may walk through, the one it starts in
 * included; a deeper path is not judged.
 */
#define OPENAT_ORACLE_DIRS	16

struct openat_dir_seen {
	dev_t dev;
	ino_t ino;
	struct timespec ctime;
};

/*
 * What sanitise_openat() saw for the oracle in post_openat(): the inode the
 * path named before the call and its ctime, the unique id of the mount it
 * lay on (0 when statx() could not give one), the directories it walked
 * through, whether every ctime recorded marks a change after it
 * (ctime_marks_change(), going by the coarse clock read before the lookups),
 * and the (dfd, path, flags) of that call.
 */
#define OPENAT_POST_STATE_MAGIC	0x4F504154UL	/* "OPAT" */
struct openat_post_state {
	unsigned long magic;
	unsigned long dfd;
	unsigned long path;
	unsigned long flags;
	dev_t dev;
	ino_t ino;
	struct timespec ctime;
	unsigned long long mnt_id;
	struct timespec before;
	bool ctimes_mark_change;
	unsigned int ndirs;
	struct openat_dir_seen dirs[OPENAT_ORACLE_DIRS];
};

/*
 * Record in @snap, or with @check compare with what it recorded, each
 * directory @path walks through before its last component: / or the
 * working directory it starts in, then the prefix up to each '/'.  A
 * directory that moves away and comes back changes the ctime of the one it
 * moved through, which the lookups of the whole path never look at, so
 * recording also clears snap->ctimes_mark_change for a directory whose
 * ctime would not show the move.  Every prefix has to be a directory: a
 * symlink there, a procfs magic link among them, can be repointed and
 * restored past what any lookup sees.  False when the path cannot be
 * judged, and when checking, when a directory differs from what was
 * recorded.
 */
static bool openat_dirs_seen(const char *path, struct openat_post_state *snap,
			     bool check)
{
	char prefix[PATH_MAX];
	size_t len = strnlen(path, sizeof(prefix)), end, i;
	const char *last;
	unsigned int n = 0;

	if (len == sizeof(prefix))
		return false;
	memcpy(prefix, path, len + 1);
	last = strrchr(prefix, '/');
	end = last != NULL ? (size_t) (last - prefix) : 0;

	for (i = 0; i <= end; i++) {
		struct openat_dir_seen *seen;
		unsigned long long mnt_id = 0;
		const char *dir = prefix;
		struct stat st;
		int ret;

		if (i != 0 && (prefix[i] != '/' || prefix[i - 1] == '/'))
			continue;
		if (n == OPENAT_ORACLE_DIRS || (check && n == snap->ndirs))
			return false;

		if (i == 0)
			dir = prefix[0] == '/' ? "/" : ".";
		else
			prefix[i] = '\0';
		ret = lstat(dir, &st);
		if (ret == 0 && !check)
			mnt_id = stat_mnt_id(AT_FDCWD, dir,
					     AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT,
					     st.st_dev, st.st_ino);
		if (i != 0)
			prefix[i] = '/';
		if (ret != 0 || !S_ISDIR(st.st_mode))
			return false;

		seen = &snap->dirs[n++];
		if (!check) {
			seen->dev = st.st_dev;
			seen->ino = st.st_ino;
			seen->ctime = st.st_ctim;
			if (!ctime_marks_change(mnt_id, &st.st_ctim, &snap->before))
				snap->ctimes_mark_change = false;
		} else if (seen->dev != st.st_dev || seen->ino != st.st_ino ||
			   seen->ctime.tv_sec != st.st_ctim.tv_sec ||
			   seen->ctime.tv_nsec != st.st_ctim.tv_nsec) {
			return false;
		}
	}

	if (check)
		return n == snap->ndirs;
	snap->ndirs = n;
	return true;
}

/*
 * Whether @path ends in a name.  A last component that is empty, "." or
 * "..", as after a trailing '/', has the walk follow a symlink before it,
 * lstat()'s included.
 */
static bool path_ends_in_a_name(const char *path)
{
	const char *last = strrchr(path, '/');

	last = last != NULL ? last + 1 : path;
	return strcmp(last, "") != 0 && strcmp(last, ".") != 0 &&
	       strcmp(last, "..") != 0;
}

static void sanitise_openat(struct syscallrecord *rec)
{
	struct stat st;
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

	if (ONE_IN(4))
		rec->a3 |= O_CREAT;

	if (rec->a3 & O_CREAT)
		rec->a4 = 0666;

	if (rec->a3 & O_TMPFILE)
		rec->a4 = 0666;

	/*
	 * Look the path up for the oracle in post_openat(), for the shape it
	 * judges, and the directories it walks through with it.  A symlink is
	 * left out: a procfs magic link can move and come back between two
	 * lookups, and its fd is the target's, which fstatfs() cannot place.
	 * So is a path through one (openat_dirs_seen()), and a path that does
	 * not end in a name, whose lookup follows a final symlink as the open
	 * does, past what S_ISLNK() can see.  The name is read only once
	 * lstat() has, so the kernel has seen a string there.  O_NOFOLLOW
	 * changes only what a trailing symlink opens, so any other path is
	 * judged with it or without.  The coarse clock is read before the
	 * lookups, for ctime_marks_change().
	 */
	if ((rec->a3 & O_PATH) &&
	    (int) rec->a1 == AT_FDCWD && rec->a2 != 0) {
		const char *path = (const char *) rec->a2;
		struct openat_post_state seen = { 0 }, *snap;

		clock_gettime(CLOCK_REALTIME_COARSE, &seen.before);
		if (lstat(path, &st) != 0 || S_ISLNK(st.st_mode) ||
		    !path_ends_in_a_name(path))
			return;
		seen.ctimes_mark_change = true;
		if (!openat_dirs_seen(path, &seen, false))
			return;
		seen.mnt_id = stat_mnt_id(AT_FDCWD, path,
					  AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT,
					  st.st_dev, st.st_ino);
		if (!ctime_marks_change(seen.mnt_id, &st.st_ctim, &seen.before))
			seen.ctimes_mark_change = false;

		snap = zmalloc_tracked(sizeof(*snap));
		*snap = seen;
		snap->magic = OPENAT_POST_STATE_MAGIC;
		snap->dfd = rec->a1;
		snap->path = rec->a2;
		snap->flags = rec->a3;
		snap->dev = st.st_dev;
		snap->ino = st.st_ino;
		snap->ctime = st.st_ctim;
		post_state_install(rec, snap);
	}
}

/*
 * Pool the file or directory an open-family call returned, and close
 * anything else.  The fd points at a random filesystem path, so none of
 * the providers (/dev, /proc, /sys, testfiles) owns it: left open and
 * unpooled, every successful call would leak one in the child until its
 * fd table filled.  pool_open_result() says what the pool takes.  open,
 * open_by_handle_at and creat share this handler.
 */
void post_open_fd(struct syscallrecord *rec)
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
		close(fd);
		return;
	}

	if (!pool_open_result(fd, &st))
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
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.sanitise = sanitise_open,
	.post = post_open_fd,
	.group = GROUP_VFS_IO,
};

/*
 * Oracle: openat(AT_FDCWD, path, O_PATH) must return an fd on the inode the
 * path names.  The open and a later lookup are separate walks, so the path is
 * looked up before the call too: a mismatch counts only when both lookups
 * agree and the fd differs from both, and lookups that disagree are
 * inconclusive.  They have to agree on the inode's ctime as well, and on the
 * directories the path walks through: the path can name another inode for
 * the open and the first one again by the later lookup only if that one, or
 * a directory on the way, was renamed away and back or linked there again,
 * and either sets a ctime the lookups compare (a write in the window does
 * too, and leaves the call unjudged).  A set ctime shows only where it is
 * sure to differ from the one recorded: on a multigrain filesystem, or for
 * a ctime older than any grain the coarse clock stamps in
 * (ctime_marks_change()).  Anywhere else a rename away and back inside one
 * tick leaves every ctime as it was, and a call that rests on such a ctime
 * is inconclusive.  A mount over the path for the open alone changes no
 * lookup, so the fd has to lie on the path's mount as well.  Symlinks,
 * paths through them and procfs fds are skipped.
 */
static void openat_path_oracle(const struct syscallrecord *rec,
			       struct openat_post_state *snap,
			       int fd, const struct stat *st_fd)
{
	struct stat st_path;
	struct statfs sfs;

	/*
	 * A slot a chain substitution or a RedQueen pin rewrote after the
	 * sanitiser makes this another call.
	 */
	if (rec->a1 != snap->dfd || rec->a2 != snap->path ||
	    rec->a3 != snap->flags)
		return;

	if (fstatfs(fd, &sfs) == 0 && sfs.f_type == PROC_SUPER_MAGIC)
		return;

	if (lstat((const char *) snap->path, &st_path) != 0 ||
	    st_path.st_dev != snap->dev || st_path.st_ino != snap->ino ||
	    st_path.st_ctim.tv_sec != snap->ctime.tv_sec ||
	    st_path.st_ctim.tv_nsec != snap->ctime.tv_nsec ||
	    !openat_dirs_seen((const char *) snap->path, snap, true))
		goto inconclusive;

	if (st_fd->st_dev == snap->dev && st_fd->st_ino == snap->ino)
		return;

	if (!snap->ctimes_mark_change)
		goto inconclusive;

	/*
	 * A mount that covers the path, or a directory on it, for the open
	 * alone puts the fd on another mount than the lookup before the call
	 * ended on, and changes neither lookup: an fd on another mount than
	 * the path's is no evidence either way, nor is one when the path's
	 * mount is not known.
	 */
	if (snap->mnt_id == 0 ||
	    stat_mnt_id(fd, "", AT_EMPTY_PATH, st_fd->st_dev,
			st_fd->st_ino) != snap->mnt_id)
		goto inconclusive;

	/*
	 * An automount trigger opened with O_DIRECTORY puts the fd on the root
	 * of what it mounted, while lstat() leaves the trigger alone and stays
	 * on it (follow_automount()): a directory fd on another filesystem
	 * than the path's is no evidence either way.
	 */
	if (S_ISDIR(st_fd->st_mode) && st_fd->st_dev != snap->dev)
		goto inconclusive;

	output(0, "fd oracle: openat(%s, O_PATH) inode mismatch "
	       "fd=(%lu:%lu) path=(%lu:%lu)\n",
	       (const char *) snap->path,
	       (unsigned long) st_fd->st_dev,
	       (unsigned long) st_fd->st_ino,
	       (unsigned long) st_path.st_dev,
	       (unsigned long) st_path.st_ino);
	__atomic_add_fetch(&shm->stats.oracle.fd_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);
	return;

inconclusive:
	__atomic_add_fetch(&shm->stats.oracle.openat_oracle_inconclusive, 1,
			   __ATOMIC_RELAXED);
}

static void post_openat(struct syscallrecord *rec)
{
	struct openat_post_state *snap;
	int fd = rec->retval;
	struct stat st_fd;

	/* Claimed first so every exit releases it, a failed call's too. */
	snap = post_state_claim_owned(rec, OPENAT_POST_STATE_MAGIC, __func__);

	if (fd < 0 || fd >= (1 << 20))
		goto out;

	if (fstat(fd, &st_fd) != 0) {
		output(0, "fd oracle: openat returned fd %d but "
		       "fstat failed (errno %d)\n", fd, errno);
		__atomic_add_fetch(&shm->stats.oracle.fd_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
		close(fd);
		goto out;
	}

	if (snap != NULL)
		openat_path_oracle(rec, snap, fd, &st_fd);

	if (!pool_open_result(fd, &st_fd))
		close(fd);

out:
	post_state_release(rec, snap);
}

/*
 * The backstop for a call that never reaches .post; a no-op once .post has
 * released it.
 */
static void cleanup_openat(struct syscallrecord *rec)
{
	post_state_release(rec, (void *) rec->post_state);
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
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.sanitise = sanitise_openat,
	.post = post_openat,
	.cleanup = cleanup_openat,
	.group = GROUP_VFS_IO,
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

	if (ONE_IN(4))
		how->flags |= O_CREAT;

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
	struct stat st;

	/*
	 * Bound the returned fd before close().  -1 is the documented
	 * failure return.  Any other out-of-range value is the fingerprint
	 * of a torn / sign-extended retval that would steer close() at a
	 * foreign fd in our own process; log + bump the corruption counter.
	 * Mirrors the bound used by the post_open_fd / post_openat siblings.
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

	if (fstat(fd, &st) != 0 || !pool_open_result(fd, &st))
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
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.sanitise = sanitise_openat2,
	.post = post_openat2,
	.cleanup = cleanup_openat2,
	.group = GROUP_VFS_IO,
};

/*
 * open_by_handle_at's arg2 is a struct file_handle __user *, not a pathname,
 * so it cannot share sanitise_openat -- that helper's testfile-path repoint
 * clobbers a2 with a NUL-terminated C string on half the draws and the
 * kernel bails out of do_handle_open() at the handle_bytes > MAX_HANDLE_SZ
 * check before exportfs_decode_fh() ever runs.  ARG_STRUCT_PTR_IN already
 * hands the kernel a plausible file_handle, so all this sanitiser has to do
 * is fold random O_* flags into arg3.  O_CREAT / O_EXCL / O_TRUNC are
 * rejected by do_handle_open(), so unlike sanitise_openat we do not OR in
 * O_CREAT and do not set a mode.
 */
static void sanitise_open_by_handle_at(struct syscallrecord *rec)
{
	rec->a3 |= get_o_flags();
}

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
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.sanitise = sanitise_open_by_handle_at,
	.post = post_open_fd,
	.group = GROUP_VFS_IO,
};
