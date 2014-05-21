#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>

#include "perf.h"
#include "shm.h"
#include "log.h"
#include "sanitise.h"

int open_perf_fds(void)
{
	unsigned int i = 0;

	while (i < MAX_PERF_FDS) {
		struct syscallrecord* sc;
		int fd;

		sc = &shm->syscall[0];
		sanitise_perf_event_open(0, sc);

		fd = syscall(__NR_perf_event_open, sc->a1, sc->a2, sc->a3, sc->a4, sc->a5);
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

int get_rand_perf_fd(void)
{
	return shm->perf_fds[rand() % MAX_PERF_FDS];
}
