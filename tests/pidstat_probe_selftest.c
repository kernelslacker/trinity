/*
 * Self-checks for utils/pidstat-probe.c.
 *
 * pidstat_task_gone() replaced a kill(pid, 0) liveness probe in the
 * reap path, because kill() asks about a pid *number* and therefore
 * lies once the kernel recycles that number onto an unrelated
 * process.  The replacement is only sound because of a procfs
 * property that nothing in this tree controls: a read through an fd
 * opened on /proc/<pid>/stat fails once the task struct behind it is
 * released, and keeps succeeding while the task merely exited and is
 * waiting to be reaped.  If that ever changes, the reap path silently
 * goes back to leaking slots -- so pin the behaviour with a test
 * rather than trusting the comment that asserts it.
 *
 *   - probe_no_fd:      fd < 0 means "no oracle", not "task gone".
 *                       Callers whose open failed soft must keep
 *                       their old fallback instead of reaping a slot
 *                       whose child may well be running.
 *
 *   - probe_live_self:  an fd on our own /proc/self/stat reads, so a
 *                       live task is never reported gone.
 *
 *   - probe_zombie_then_gone: fork a child that exits immediately,
 *                       open its stat file, and prove the probe says
 *                       "not gone" while it is an unreaped zombie
 *                       (the waitpid(-1) drain owns those), then says
 *                       "gone" after the wait releases the task.
 *
 * The fork here is the only one in the test binary.  It is a bare
 * fork/_exit/waitpid with no shm and no trinity state, and the parent
 * waits for it before returning, so nothing outlives the check.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"			/* BUG */
#include "pidstat-probe.h"
#include "utils.h"			/* waitpid_eintr */

static int open_pidstat(pid_t pid)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);

	return open(path, O_RDONLY | O_CLOEXEC);
}

static void selftest_no_fd(void)
{
	if (pidstat_task_gone(-1) != false)
		BUG("pidstat probe: fd -1 must not report the task gone");
}

static void selftest_live_self(void)
{
	int fd;

	fd = open_pidstat(getpid());
	if (fd < 0)
		BUG("pidstat probe: cannot open own /proc/<pid>/stat");

	if (pidstat_task_gone(fd) != false)
		BUG("pidstat probe: live task reported gone");

	close(fd);
}

static void selftest_zombie_then_gone(void)
{
	pid_t pid, waited;
	int fd, status;

	pid = fork();
	if (pid < 0)
		BUG("pidstat probe: fork failed");

	if (pid == 0)
		_exit(0);

	/* The child may be running or already a zombie by the time we
	 * get here; either way its stat file exists and reads, which is
	 * the point -- an exited-but-unreaped task is not "gone". */
	fd = open_pidstat(pid);
	if (fd < 0)
		BUG("pidstat probe: cannot open child /proc/<pid>/stat");

	if (pidstat_task_gone(fd) != false)
		BUG("pidstat probe: unreaped child reported gone");

	waited = waitpid_eintr(pid, &status, 0);
	if (waited != pid)
		BUG("pidstat probe: waitpid did not reap the child");

	if (pidstat_task_gone(fd) != true)
		BUG("pidstat probe: reaped child not reported gone");

	close(fd);
}

void pidstat_probe_self_check(void);
void pidstat_probe_self_check(void)
{
	selftest_no_fd();
	selftest_live_self();
	selftest_zombie_then_gone();
}
