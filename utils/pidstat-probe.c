#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

#include "pidstat-probe.h"

/*
 * Task-identity liveness probe.
 *
 * A `kill(pid, 0)` probe answers a question about a pid *number*, not
 * about a task.  Once the kernel has recycled that number onto an
 * unrelated process the probe succeeds, so a dead child reads as
 * alive: its slot is never reaped, and the pid keeps being handed to
 * the process-targeting syscalls (kill, ptrace, ...) for the rest of
 * the run -- now aimed at a stranger.  The failure mode is
 * self-reinforcing, because the recycle is exactly what makes the
 * detector lie.
 *
 * An fd opened on /proc/<pid>/stat while the task existed is pinned to
 * that task rather than to the number, so it cannot be spoofed by a
 * recycle: procfs answers ESRCH once the task struct is released, no
 * matter who owns the pid now.  A zombie still reads fine (state Z) --
 * a task that has exited but not been waited for is not "gone" here,
 * which is what callers reaping via waitpid() want.
 *
 * Returns false when there is no fd to ask, so a caller whose fd open
 * failed soft can fall back to whatever it did before rather than
 * treating an unopenable slot as dead.
 */
bool pidstat_task_gone(int fd)
{
	char buf[64];
	ssize_t n;

	if (fd < 0)
		return false;

	n = TEMP_FAILURE_RETRY(pread(fd, buf, sizeof(buf), 0));

	return (n <= 0);
}
