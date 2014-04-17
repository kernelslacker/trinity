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

void open_perf_fds(void)
{
	struct syscallrecord* sc;
	unsigned int i = 0;

	while (i < MAX_PERF_FDS) {
		int fd;

		sanitise_perf_event_open(0);
		sc = &shm->syscall[0];
		fd = syscall(__NR_perf_event_open, sc->a1, sc->a2, sc->a3, sc->a4, sc->a5);
		if (fd != -1) {
			shm->perf_fds[i] = fd;
			output(2, "fd[%d] = perf\n", shm->perf_fds[i]);
			i++;
		} else {
			if (errno == ENOSYS)
				return;
		}
	}
}

int rand_perf_fd(void)
{
	return shm->perf_fds[rand() % MAX_PERF_FDS];
}
