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
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "childops-util.h"
#include "shm.h"
#include "userns-bootstrap.h"

/*
 * Grandchild exit codes.  Each setup failure gets a distinct value so
 * a post-mortem debugger can recover the failure mode from the wait
 * status, even though the parent collapses 2-4 into a single -1.
 */
#define UBS_EXIT_RAN              0
#define UBS_EXIT_USERNS_EPERM     1
#define UBS_EXIT_USERNS_OTHER     2
#define UBS_EXIT_MAP_WRITE_FAIL   3
#define UBS_EXIT_TARGET_UNSHARE   4

/*
 * Write a single short line to one of the proc id-map files.  The
 * kernel consumes the whole buffer or rejects it atomically, so a
 * short write is treated as failure.
 */
static bool write_one_line(const char *path, const char *line)
{
	ssize_t wlen;
	size_t len;
	int fd;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return false;

	len = strlen(line);
	wlen = write(fd, line, len);
	close(fd);
	return wlen == (ssize_t)len;
}

/*
 * Install the identity uid/gid map inside the freshly-entered userns.
 * Single-line "0 <real> 1" maps cover the one identity we need and
 * keep the writer out of the newuidmap / subuid range path entirely.
 * setgroups must be denied BEFORE gid_map can be written by an
 * unprivileged writer.
 */
static bool install_identity_maps(void)
{
	char buf[64];
	uid_t uid = getuid();
	gid_t gid = getgid();

	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned int)uid);
	if (!write_one_line("/proc/self/uid_map", buf))
		return false;

	if (!write_one_line("/proc/self/setgroups", "deny\n"))
		return false;

	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned int)gid);
	if (!write_one_line("/proc/self/gid_map", buf))
		return false;

	return true;
}

/*
 * Grandchild body.  Every exit path uses _exit() to skip atexit
 * handlers -- those might touch trinity shared state with a
 * capability profile the rest of the fuzzer doesn't expect.
 */
static void grandchild_body(int target_ns_flags,
			    int (*fn)(void *), void *arg)
{
	if (unshare(CLONE_NEWUSER) != 0) {
		if (errno == EPERM)
			_exit(UBS_EXIT_USERNS_EPERM);
		_exit(UBS_EXIT_USERNS_OTHER);
	}

	if (!install_identity_maps())
		_exit(UBS_EXIT_MAP_WRITE_FAIL);

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
		case UBS_EXIT_MAP_WRITE_FAIL:
			__atomic_add_fetch(&shm->stats.userns_bootstrap_map_write_fail,
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
