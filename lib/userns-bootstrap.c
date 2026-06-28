/*
 * userns_run_in_ns() -- see include/userns-bootstrap.h for the full
 * contract.  This is the transient-fork implementation modelled on
 * childops/userns-fuzzer.c's inner_child_main() and outer parent
 * (fork/_exit/waitpid).  It is generalised so any caller can request
 * an identity-mapped userns plus arbitrary secondary namespaces.
 *
 * The order inside the grandchild is fixed and matches the kernel's
 * documented requirements:
 *   1. unshare(CLONE_NEWUSER)               -- enter a fresh userns
 *   2. write /proc/self/uid_map "0 <uid> 1" -- single-line identity map
 *   3. write /proc/self/setgroups "deny"    -- required before gid_map
 *                                              for an unprivileged
 *                                              writer (Documentation/
 *                                              admin-guide/namespaces/
 *                                              user.rst)
 *   4. write /proc/self/gid_map "0 <gid> 1" -- single-line identity map
 *   5. unshare(target_ns_flags) if non-zero -- ns_capable now granted
 *                                              by the userns above
 *   6. fn(arg); _exit(...)                  -- single fork/exit per call
 *
 * setns() is never called from the grandchild -- in particular never
 * into an init-namespace fd -- so the grandchild cannot escape into
 * the host's namespace stack and its caps remain firewalled to the
 * fresh userns.
 */

#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "childops-util.h"
#include "shm.h"
#include "userns-bootstrap.h"

/*
 * Grandchild exit codes.  Each setup failure gets a distinct value so
 * a post-mortem debugger can recover the failure mode from the wait
 * status, even though the parent collapses 2-4 into a single -1.
 *
 * MAP_WRITE_FAIL is split into per-errno buckets so a post-geteuid
 * residual failure (EPERM from a still-mismatched mapping, EINVAL
 * from a malformed line or a writer that lost the unprivileged single-
 * line rule, open() of a missing file, short write) is diagnosable
 * from stats alone instead of collapsing into one opaque slot.  The
 * historical UBS_EXIT_MAP_WRITE_FAIL value (3) is the "other" bucket
 * so existing post-mortem readers do not need a value remap.
 */
#define UBS_EXIT_RAN                    0
#define UBS_EXIT_USERNS_EPERM           1
#define UBS_EXIT_USERNS_OTHER           2
#define UBS_EXIT_MAP_WRITE_FAIL_OTHER   3
#define UBS_EXIT_TARGET_UNSHARE         4
#define UBS_EXIT_MAP_WRITE_FAIL_EPERM   5
#define UBS_EXIT_MAP_WRITE_FAIL_EINVAL  6

/*
 * Translate the errno captured at the failing id-map write site into
 * the matching grandchild exit code.  Bucketed to keep the exit-code
 * alphabet small and stable: EPERM and EINVAL cover the kernel's two
 * documented rejections of the unprivileged single-line idmap rule;
 * everything else (open() ENOENT/EACCES, short write, EIO, ...) lands
 * in the OTHER bucket which retains the historical value.
 */
static int map_write_exit_code(int saved_errno)
{
	switch (saved_errno) {
	case EPERM:
		return UBS_EXIT_MAP_WRITE_FAIL_EPERM;
	case EINVAL:
		return UBS_EXIT_MAP_WRITE_FAIL_EINVAL;
	default:
		return UBS_EXIT_MAP_WRITE_FAIL_OTHER;
	}
}

/*
 * Write a single short line to one of the proc id-map files.  The
 * kernel consumes the whole buffer or rejects it atomically, so a
 * short write is treated as failure.  Returns 0 on success, otherwise
 * the errno of the failing open()/write() so the caller can route it
 * to the matching per-errno exit bucket.  A short write that does not
 * set errno is reported as EIO.
 */
static int write_one_line(const char *path, const char *line)
{
	ssize_t wlen;
	size_t len;
	int fd, saved;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return errno ? errno : EIO;

	len = strlen(line);
	wlen = write(fd, line, len);
	saved = errno;
	close(fd);
	if (wlen == (ssize_t)len)
		return 0;
	if (wlen < 0)
		return saved ? saved : EIO;
	return EIO;
}

/*
 * Install the identity uid/gid map inside the freshly-entered userns.
 * Single-line "0 <real> 1" maps cover the one identity we need and
 * keep the writer out of the newuidmap / subuid range path entirely.
 * setgroups must be denied BEFORE gid_map can be written by an
 * unprivileged writer.  Returns 0 on success, otherwise the errno of
 * the first failing write so the grandchild can encode it into its
 * exit code.
 */
static int install_identity_maps(uid_t uid, gid_t gid)
{
	char buf[64];
	int err;

	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned int)uid);
	err = write_one_line("/proc/self/uid_map", buf);
	if (err != 0)
		return err;

	err = write_one_line("/proc/self/setgroups", "deny\n");
	if (err != 0)
		return err;

	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned int)gid);
	return write_one_line("/proc/self/gid_map", buf);
}

/*
 * Grandchild body.  Every exit path uses _exit() to skip atexit
 * handlers -- those might touch trinity shared state with a
 * capability profile the rest of the fuzzer doesn't expect.
 */
static void grandchild_body(int target_ns_flags,
			    int (*fn)(void *), void *arg)
{
	int map_err;

	/*
	 * Capture the parent-ns effective uid/gid BEFORE unshare(CLONE_NEWUSER).
	 * After the unshare and before any map is written, the geteuid and
	 * getegid getters return the overflow id (65534); the single-line
	 * unprivileged idmap rule requires the mapped outside id to equal the
	 * opener's effective uid/gid in the parent ns, so writing anything else
	 * yields EPERM.  Trinity's setuid-family fuzz (setreuid/setresuid/
	 * setfsuid/...) can leave ruid != euid in the persistent child; the
	 * grandchild inherits that, so reading getuid()/getgid() and comparing
	 * against the kernel's euid check is racy.  geteuid()/getegid() are
	 * tautologically correct: write our current euid, kernel checks our
	 * current euid.
	 */
	uid_t uid = geteuid();
	gid_t gid = getegid();

	if (unshare(CLONE_NEWUSER) != 0) {
		if (errno == EPERM)
			_exit(UBS_EXIT_USERNS_EPERM);
		_exit(UBS_EXIT_USERNS_OTHER);
	}

	map_err = install_identity_maps(uid, gid);
	if (map_err != 0)
		_exit(map_write_exit_code(map_err));

	if (target_ns_flags != 0 && unshare(target_ns_flags) != 0)
		_exit(UBS_EXIT_TARGET_UNSHARE);

	(void)fn(arg);
	_exit(UBS_EXIT_RAN);
}

int userns_run_in_ns(int target_ns_flags, int (*fn)(void *), void *arg)
{
	pid_t pid;
	int status;

	if (fn == NULL)
		return -EAGAIN;

	__atomic_add_fetch(&shm->stats.userns_bootstrap_runs,
	                   1, __ATOMIC_RELAXED);

	pid = fork();
	if (pid < 0) {
		__atomic_add_fetch(&shm->stats.userns_bootstrap_fork_fail,
		                   1, __ATOMIC_RELAXED);
		return -EAGAIN;
	}

	if (pid == 0) {
		grandchild_body(target_ns_flags, fn, arg);
		_exit(UBS_EXIT_USERNS_OTHER);	/* unreachable */
	}

	if (waitpid_eintr(pid, &status, 0) < 0)
		return -EAGAIN;

	if (WIFEXITED(status)) {
		switch (WEXITSTATUS(status)) {
		case UBS_EXIT_RAN:
			__atomic_add_fetch(&shm->stats.userns_bootstrap_ran,
			                   1, __ATOMIC_RELAXED);
			return 0;
		case UBS_EXIT_USERNS_EPERM:
			__atomic_add_fetch(&shm->stats.userns_bootstrap_eperm,
			                   1, __ATOMIC_RELAXED);
			return -EPERM;
		case UBS_EXIT_USERNS_OTHER:
			__atomic_add_fetch(&shm->stats.userns_bootstrap_userns_other,
			                   1, __ATOMIC_RELAXED);
			return -EAGAIN;
		case UBS_EXIT_MAP_WRITE_FAIL_OTHER:
			__atomic_add_fetch(&shm->stats.userns_bootstrap_map_write_fail,
			                   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.userns_bootstrap_map_write_fail_other,
			                   1, __ATOMIC_RELAXED);
			return -EAGAIN;
		case UBS_EXIT_MAP_WRITE_FAIL_EPERM:
			__atomic_add_fetch(&shm->stats.userns_bootstrap_map_write_fail,
			                   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.userns_bootstrap_map_write_fail_eperm,
			                   1, __ATOMIC_RELAXED);
			return -EAGAIN;
		case UBS_EXIT_MAP_WRITE_FAIL_EINVAL:
			__atomic_add_fetch(&shm->stats.userns_bootstrap_map_write_fail,
			                   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.userns_bootstrap_map_write_fail_einval,
			                   1, __ATOMIC_RELAXED);
			return -EAGAIN;
		case UBS_EXIT_TARGET_UNSHARE:
			__atomic_add_fetch(&shm->stats.userns_bootstrap_target_unshare,
			                   1, __ATOMIC_RELAXED);
			return -EAGAIN;
		default:
			__atomic_add_fetch(&shm->stats.userns_bootstrap_userns_other,
			                   1, __ATOMIC_RELAXED);
			return -EAGAIN;
		}
	}

	/* Signalled or stopped -- treat as transient failure, no latch. */
	__atomic_add_fetch(&shm->stats.userns_bootstrap_signalled,
	                   1, __ATOMIC_RELAXED);
	return -EAGAIN;
}
