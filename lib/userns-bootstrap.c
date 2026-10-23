/*
 * userns_run_in_ns(): fork a transient grandchild, enter an identity-mapped
 * user namespace plus any secondary namespaces, run the callback, _exit().
 * Contract: include/userns-bootstrap.h; rationale:
 * Documentation/userns-bootstrap.md.  The grandchild never calls setns(), so
 * its capabilities stay confined to the fresh user namespace.
 */

#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "childops-util.h"
#include "pids.h"
#include "shm.h"
#include "signals.h"
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
 *
 * PARENT_GONE is a parent that died before PDEATHSIG was armed.  No one
 * is left to wait for it, but it keeps its own value so that it can never
 * read as the userns EPERM, which latches a childop off.
 */
#define UBS_EXIT_RAN                    0
#define UBS_EXIT_USERNS_EPERM           1
#define UBS_EXIT_USERNS_OTHER           2
#define UBS_EXIT_MAP_WRITE_FAIL_OTHER   3
#define UBS_EXIT_TARGET_UNSHARE         4
#define UBS_EXIT_MAP_WRITE_FAIL_EPERM   5
#define UBS_EXIT_MAP_WRITE_FAIL_EINVAL  6
#define UBS_EXIT_PARENT_GONE            7

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
 * Has the parent that forked us exited?  Its pidfd turns readable once it
 * has, whichever pid namespace we are in.  getppid() reads 0 when we were
 * forked into a pid namespace the parent is not in (a child that unshared
 * CLONE_NEWPID), whether or not the parent is alive, so without a pidfd
 * only a pid that is neither the parent's nor 0 proves it gone.
 */
static bool parent_gone(int parent_pidfd, pid_t expected_ppid)
{
	struct pollfd pfd = { .fd = parent_pidfd, .events = POLLIN };
	pid_t ppid;

	if (parent_pidfd >= 0)
		return poll(&pfd, 1, 0) > 0;
	ppid = getppid();
	return ppid != expected_ppid && ppid != 0;
}

/*
 * Grandchild body.  Every exit path uses _exit() to skip atexit
 * handlers -- those might touch trinity shared state with a
 * capability profile the rest of the fuzzer doesn't expect.
 *
 * The order is fixed: unshare(CLONE_NEWUSER), the id-map writes, the
 * secondary unshare(target_ns_flags), then fn(arg).  The secondary
 * unshare needs the ns_capable() that only the new userns grants.
 */
static void grandchild_body(int target_ns_flags,
			    int (*fn)(void *), void *arg,
			    pid_t expected_ppid, int parent_pidfd)
{
	int map_err;
	/*
	 * If the trinity child (our parent process) is killed before we
	 * exit -- for example by the reap-watchdog SIGKILL at
	 * REAP_STALL_THRESHOLD_S seconds of no progress -- ensure the
	 * grandchild is also killed rather than reparented and left running
	 * indefinitely.  PR_SET_PDEATHSIG delivers SIGKILL to this process
	 * when its parent terminates after this point.
	 */
	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	/*
	 * PDEATHSIG does not cover a parent that died between fork()
	 * returning and the prctl() above, so look for one here.  The parent
	 * is the trinity worker that called us (expected_ppid, its getpid()
	 * just before the fork), not mainpid, the orchestrator.
	 */
	if (parent_gone(parent_pidfd, expected_ppid))
		_exit(UBS_EXIT_PARENT_GONE);
	if (parent_pidfd >= 0)
		close(parent_pidfd);

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

	/*
	 * Cap the callback's run-time.  The grandchild is reached via
	 * plain fork() with no execve(), so signal handlers installed
	 * by the trinity child (including the SIGALRM flag-setter from
	 * health/signals-policy.c) are inherited.  unshare(CLONE_NEWUSER)
	 * does not reset dispositions.  Reset SIGALRM to SIG_DFL so
	 * that alarm() actually terminates this disposable grandchild
	 * when fn(arg) blocks; with the inherited handler the signal
	 * would merely set a flag and return, leaving the grandchild
	 * running and the one-shot alarm consumed.
	 */
	signal(SIGALRM, SIG_DFL);
	alarm(USERNS_CALLBACK_ALARM_S);
	(void)fn(arg);
	_exit(UBS_EXIT_RAN);
}

int userns_run_in_ns(int target_ns_flags, int (*fn)(void *), void *arg)
{
	pid_t pid;
	int status;

	if (fn == NULL)
		return -EAGAIN;

	__atomic_add_fetch(&shm->stats.userns_bootstrap.runs,
	                   1, __ATOMIC_RELAXED);

	pid_t expected_ppid = getpid();
	int parent_pidfd = -1;

#ifdef __NR_pidfd_open
	parent_pidfd = (int)syscall(__NR_pidfd_open, expected_ppid, 0);
#endif
	pid = fork();
	if (pid == 0) {
		grandchild_body(target_ns_flags, fn, arg, expected_ppid,
				parent_pidfd);
		_exit(UBS_EXIT_USERNS_OTHER);	/* unreachable */
	}
	if (parent_pidfd >= 0)
		close(parent_pidfd);
	if (pid < 0) {
		__atomic_add_fetch(&shm->stats.userns_bootstrap.fork_fail,
		                   1, __ATOMIC_RELAXED);
		return -EAGAIN;
	}

	/*
	 * Belt-and-suspenders parent-side timeout.  The grandchild now
	 * resets SIGALRM to SIG_DFL before arming alarm(), so a wedged
	 * fn() is terminated by the grandchild's own alarm and
	 * waitpid_eintr() returns normally via the resulting SIGCHLD.
	 * The parent alarm (USERNS_PARENT_ALARM_S > USERNS_CALLBACK_ALARM_S)
	 * is a secondary escape for the unlikely case the grandchild's
	 * alarm fails to fire.
	 *
	 * Save and restore the caller's pending alarm: alarm(N) replaces
	 * any existing pending alarm and returns the remaining seconds.
	 * Without save/restore, child.c's 1-second stall watchdog
	 * (alarm(1) set before every alt-op) is clobbered and then
	 * cancelled by the alarm(0) below, leaving the op with no inner
	 * stall detection.
	 *
	 * Note: waitpid_eintr() retries through EINTR, so the parent's
	 * SIGALRM will not permanently interrupt the wait -- it fires the
	 * flag-setter, the loop re-blocks, and no escalation to SIGKILL
	 * occurs from the parent side.  The grandchild-side SIG_DFL
	 * reset (above) is what makes the cap real.
	 */
	unsigned int rem = alarm(USERNS_PARENT_ALARM_S);
	if (waitpid_eintr(pid, &status, 0) < 0) {
		alarm(rem);
		return -EAGAIN;
	}
	alarm(rem);

	if (WIFEXITED(status)) {
		switch (WEXITSTATUS(status)) {
		case UBS_EXIT_RAN:
			__atomic_add_fetch(&shm->stats.userns_bootstrap.ran,
			                   1, __ATOMIC_RELAXED);
			return 0;
		case UBS_EXIT_USERNS_EPERM:
			__atomic_add_fetch(&shm->stats.userns_bootstrap.eperm,
			                   1, __ATOMIC_RELAXED);
			return -EPERM;
		case UBS_EXIT_USERNS_OTHER:
			__atomic_add_fetch(&shm->stats.userns_bootstrap.userns_other,
			                   1, __ATOMIC_RELAXED);
			return -EAGAIN;
		case UBS_EXIT_MAP_WRITE_FAIL_OTHER:
			__atomic_add_fetch(&shm->stats.userns_bootstrap.map_write_fail,
			                   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.userns_bootstrap.map_write_fail_other,
			                   1, __ATOMIC_RELAXED);
			return -EAGAIN;
		case UBS_EXIT_MAP_WRITE_FAIL_EPERM:
			__atomic_add_fetch(&shm->stats.userns_bootstrap.map_write_fail,
			                   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.userns_bootstrap.map_write_fail_eperm,
			                   1, __ATOMIC_RELAXED);
			return -EAGAIN;
		case UBS_EXIT_MAP_WRITE_FAIL_EINVAL:
			__atomic_add_fetch(&shm->stats.userns_bootstrap.map_write_fail,
			                   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.userns_bootstrap.map_write_fail_einval,
			                   1, __ATOMIC_RELAXED);
			return -EAGAIN;
		case UBS_EXIT_TARGET_UNSHARE:
			__atomic_add_fetch(&shm->stats.userns_bootstrap.target_unshare,
			                   1, __ATOMIC_RELAXED);
			return -EAGAIN;
		default:
			__atomic_add_fetch(&shm->stats.userns_bootstrap.userns_other,
			                   1, __ATOMIC_RELAXED);
			return -EAGAIN;
		}
	}

	/* Signalled or stopped -- treat as transient failure, no latch. */
	__atomic_add_fetch(&shm->stats.userns_bootstrap.signalled,
	                   1, __ATOMIC_RELAXED);
	return -EAGAIN;
}
