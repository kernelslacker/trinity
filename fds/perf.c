#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>

#include "fd.h"
#include "perf.h"
#include "shm.h"
#include "log.h"
#include "sanitise.h"

static int open_perf_fds(void)
{
	unsigned int i = 0;

	while (i < MAX_PERF_FDS) {
		struct syscallrecord *rec;
		int fd;

		rec = &shm->children[0]->syscall;
		sanitise_perf_event_open(rec);

		fd = syscall(__NR_perf_event_open, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5);
		if (fd != -1) {
			shm->perf_fds[i] = fd;
			output(2, "fd[%d] = perf\n", shm->perf_fds[i]);
			i++;
		} else {
			/* If ENOSYS, bail early rather than do MAX_PERF_FDS retries */
			if (errno == ENOSYS)
				return TRUE;

			/* If we get here we probably generated something invalid and
			 * perf_event_open threw it out. Go around the loop again.
			 */
		}
	}

	return TRUE;
}

static int get_rand_perf_fd(void)
{
	if (shm->perf_fds[0] == 0)	/* perf unavailable/disabled. */
		return -1;

	return shm->perf_fds[rand() % MAX_PERF_FDS];
}

const struct fd_provider perf_fd_provider = {
	.name = "perf",
	.enabled = TRUE,
	.open = &open_perf_fds,
	.get = &get_rand_perf_fd,
};
