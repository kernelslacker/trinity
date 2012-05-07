#ifndef _SHM_H
#define _SHM_H 1

#include "constants.h"

struct shm_s {
	unsigned long execcount;
	unsigned long successes;
	unsigned long failures;
	unsigned long retries;
	unsigned int regenerate;

	unsigned int nr_childs;
	unsigned int running_childs;
	pid_t pids[MAX_NR_CHILDREN];

	FILE *logfiles[MAX_NR_CHILDREN];

	unsigned int pipe_fds[MAX_PIPE_FDS*2];
	unsigned int fds[MAX_FDS/2];

	unsigned int socket_fds[MAX_FDS/2];

	unsigned int current_fd, fd_lifetime;

	unsigned char do32bit;
};
extern struct shm_s *shm;

#endif	/* _SHM_H */
