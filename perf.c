#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <asm/unistd.h>

#include "perf.h"
#include "shm.h"
#include "log.h"
#include "sanitise.h"

void open_perf_fds(void)
{
	unsigned int i = 0;

	while (i < MAX_PERF_FDS) {
		int fd;

		sanitise_perf_event_open(0);
		fd = syscall(__NR_perf_event_open, shm->syscall[0].a1, shm->syscall[0].a2, shm->syscall[0].a3, shm->syscall[0].a4, shm->syscall[0].a5);
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
