#ifndef _SHM_H
#define _SHM_H 1

#include <sys/time.h>

#include <stdio.h>

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
	int total_syscalls[MAX_NR_CHILDREN];
	struct timeval tv[MAX_NR_CHILDREN];

	FILE *logfiles[MAX_NR_CHILDREN];

	int pipe_fds[MAX_PIPE_FDS*2];
	int fds[MAX_FDS/2];
	int socket_fds[MAX_FDS/2];

	/* state for the syscall currently in progress. */
	unsigned int syscallno[MAX_NR_CHILDREN];
	unsigned long a1[MAX_NR_CHILDREN];
	unsigned long a2[MAX_NR_CHILDREN];
	unsigned long a3[MAX_NR_CHILDREN];
	unsigned long a4[MAX_NR_CHILDREN];
	unsigned long a5[MAX_NR_CHILDREN];
	unsigned long a6[MAX_NR_CHILDREN];

	int current_fd;
	unsigned int fd_lifetime;

	unsigned char do32bit;

	unsigned char exit_now;

	pid_t watchdog_pid;
};
extern struct shm_s *shm;

#endif	/* _SHM_H */
