/*
 * Self-check for userns_run_in_ns() (lib/userns-bootstrap.c) called by a
 * child that unshared a pid namespace.  Its grandchild lands in that
 * namespace, where getppid() reads 0 while the parent is alive, and must
 * not take that for a dead parent: the call would read as a userns policy
 * refusal (-EPERM) and latch its childop off.  Skipped where unprivileged
 * user namespaces are not available.
 */

#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "userns-bootstrap.h"
#include "utils.h"		/* waitpid_eintr */

/* How the helper exits when it cannot set up the namespaces. */
#define NO_USERNS	77

static int nothing(void *arg)
{
	(void)arg;
	return 0;
}

static bool write_proc(const char *path, const char *line)
{
	int fd = open(path, O_WRONLY);
	bool ok;

	if (fd < 0)
		return false;
	ok = write(fd, line, strlen(line)) == (ssize_t)strlen(line);
	close(fd);
	return ok;
}

/* In the helper: map its own ids, which the grandchild's single-line map
 * has to name; unmapped, its euid reads as the overflow id. */
static bool map_self(uid_t uid, gid_t gid)
{
	char line[64];

	snprintf(line, sizeof(line), "%u %u 1\n", (unsigned int)uid, (unsigned int)uid);
	if (!write_proc("/proc/self/uid_map", line) ||
	    !write_proc("/proc/self/setgroups", "deny\n"))
		return false;
	snprintf(line, sizeof(line), "%u %u 1\n", (unsigned int)gid, (unsigned int)gid);
	return write_proc("/proc/self/gid_map", line);
}

void userns_bootstrap_self_check(void);
void userns_bootstrap_self_check(void)
{
	uid_t uid = geteuid();
	gid_t gid = getegid();
	pid_t pid = fork();
	int status;

	if (pid < 0)
		BUG("userns_bootstrap: fork failed");
	if (pid == 0) {
		/* Don't outlive the test binary if the check aborts. */
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (unshare(CLONE_NEWUSER | CLONE_NEWPID) != 0 || !map_self(uid, gid))
			_exit(NO_USERNS);
		if (userns_run_in_ns(0, nothing, NULL) != 0)
			BUG("userns_bootstrap: a grandchild in the caller's pid namespace did not run");
		_exit(0);
	}
	if (waitpid_eintr(pid, &status, 0) != pid)
		BUG("userns_bootstrap: cannot reap the helper");
	if (WIFEXITED(status) && WEXITSTATUS(status) == NO_USERNS) {
		printf("(no unprivileged user namespaces, skipping) ");
		return;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		BUG("userns_bootstrap: the check failed in the namespace helper");
}
