#pragma once

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Restartable waitpid() for childops running under child.c's alarm(1).
 * SIGALRM and SIGXCPU are installed without SA_RESTART (signals.c), so any
 * blocking waitpid() in a non-syscall op can return -1/EINTR.  Every caller
 * here needs the wait to either complete or fail terminally; treating EINTR
 * as "done" leaves a child unreaped and, for ops that tear down a shared
 * mapping right after the wait (barrier-racer, futex-storm), leaves a worker
 * that will fault when it next touches the destroyed barrier.
 */
static inline pid_t waitpid_eintr(pid_t pid, int *status, int flags)
{
	pid_t rc;

	do {
		rc = waitpid(pid, status, flags);
	} while (rc < 0 && errno == EINTR);

	return rc;
}

/*
 * Best-effort `modprobe -q <mod>` invoked from a forked child.  stdio is
 * redirected to /dev/null so module-load chatter doesn't pollute trinity's
 * output, and the parent waits via waitpid_eintr() so the child is reaped
 * even under child.c's alarm(1).  Failure (fork/exec/missing module) is
 * silent; callers exercise the resulting interface afterwards and let it
 * fail naturally if the module isn't present.
 */
static inline void try_modprobe(const char *mod)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return;
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (devnull >= 0) {
			(void)dup2(devnull, 0);
			(void)dup2(devnull, 1);
			(void)dup2(devnull, 2);
			close(devnull);
		}
		execlp("modprobe", "modprobe", "-q", mod, (char *)NULL);
		_exit(127);
	}
	(void)waitpid_eintr(pid, &status, 0);
}
