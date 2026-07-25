#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/sched.h>

#include "child-api.h"
#include "self_cgroup.h"
#include "trinity.h"
#include "utils.h"

#include "self-cgroup-internal.h"

#include "kernel/fcntl.h"
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

static bool clone3_unavailable;	/* latched on first ENOSYS */

/*
 * Spawn a worker into the children/ cgroup.  Same return semantics as
 * fork(): pid in parent, 0 in child, -1 on error.
 *
 * Preferred path is clone3(CLONE_INTO_CGROUP) with an O_DIRECTORY fd on
 * children/ — atomic placement, no transient window where the child runs
 * in parent/ and racing allocations could land against the wrong limit.
 *
 * Fallbacks:
 *   - cg_workload_fd < 0 (cgroup setup didn't happen, or single-cgroup
 *     fallback): plain fork(); children inherit whatever cgroup the
 *     parent is in.
 *   - clone3 returns ENOSYS (very old kernel, pre-5.7-ish or stripped):
 *     latch clone3_unavailable, fall through to fork() + post-migrate
 *     by writing the child pid to children/cgroup.procs.  Brief race
 *     window where the child is in parent/ before the write lands.
 *   - clone3 returns any other error (EAGAIN, ENOMEM): return -1 so the
 *     caller's existing retry loop in spawn_child() handles it the same
 *     way it would handle a transient fork() failure.
 */
pid_t self_cgroup_fork_into_workload(void)
{
	pid_t pid;

	if (cg_workload_fd < 0)
		return fork();

	if (!clone3_unavailable) {
		struct clone_args args = {
			.flags = CLONE_INTO_CGROUP,
			.exit_signal = SIGCHLD,
			.cgroup = (uint64_t)(unsigned int)cg_workload_fd,
		};
		long ret = syscall(__NR_clone3, &args, sizeof(args));

		if (ret >= 0)
			return (pid_t)ret;
		if (errno != ENOSYS && errno != EINVAL)
			return -1;
		clone3_unavailable = true;
		output(0, "self-cgroup: clone3 %s; "
		       "falling back to fork()+post-migrate\n",
		       errno == ENOSYS ? "ENOSYS" : "EINVAL");
	}

	pid = fork();
	if (pid > 0) {
		char buf[32];
		int n = snprintf(buf, sizeof(buf), "%d\n", (int)pid);
		int fd = -1;
		bool migrated = false;

		if (n > 0 && (size_t)n < sizeof(buf)) {
			fd = openat(cg_workload_fd, "cgroup.procs",
				    O_WRONLY | O_CLOEXEC);
			if (fd >= 0) {
				ssize_t wn = write(fd, buf, (size_t)n);

				if (wn == n)
					migrated = true;
				else {
					if (wn >= 0)
						errno = EIO;
					output(0, "self-cgroup: post-fork migrate of pid %d failed: %s\n",
					       (int)pid, strerror(errno));
				}
				close(fd);
			} else {
				output(0, "self-cgroup: openat(cgroup.procs) failed for pid %d: %s\n",
				       (int)pid, strerror(errno));
			}
		} else {
			output(0, "self-cgroup: snprintf failed encoding pid %d\n", (int)pid);
		}

		if (!migrated) {
			/* Kill the child we just forked so it doesn't run outside the
			 * worker memory cap; the caller's spawn-retry path handles the
			 * -1 return. */
			kill(pid, SIGKILL);
			(void)waitpid_eintr(pid, NULL, 0);
			return -1;
		}
	}
	return pid;
}
