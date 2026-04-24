#pragma once

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

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
