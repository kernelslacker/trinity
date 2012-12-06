#ifndef _SHM_H
#define _SHM_H 1


#include <sys/time.h>

#include <stdio.h>

#include "trinity.h"
#include "constants.h"

struct shm_s {
	unsigned long total_syscalls_done;
	unsigned long successes;
	unsigned long failures;
	unsigned long previous_count;
	unsigned long child_syscall_count[MAX_NR_CHILDREN];

	unsigned long regenerate;
	unsigned int seed;
	unsigned int seeds[MAX_NR_CHILDREN];
	unsigned int reseed_counter;

	pid_t parentpid;
	pid_t watchdog_pid;
	pid_t pids[MAX_NR_CHILDREN];

	pid_t last_reaped;

	unsigned int max_children;
	unsigned int running_childs;
	struct timeval tv[MAX_NR_CHILDREN];

	FILE *logfiles[MAX_NR_CHILDREN];

	int pipe_fds[MAX_PIPE_FDS*2];
	int file_fds[NR_FILE_FDS];		/* All children inherit these */
	int socket_fds[NR_SOCKET_FDS];

	/* state for the syscall currently in progress. */
	unsigned int previous_syscallno[MAX_NR_CHILDREN];
	unsigned long previous_a1[MAX_NR_CHILDREN];
	unsigned long previous_a2[MAX_NR_CHILDREN];
	unsigned long previous_a3[MAX_NR_CHILDREN];
	unsigned long previous_a4[MAX_NR_CHILDREN];
	unsigned long previous_a5[MAX_NR_CHILDREN];
	unsigned long previous_a6[MAX_NR_CHILDREN];

	unsigned int syscallno[MAX_NR_CHILDREN];
	unsigned long a1[MAX_NR_CHILDREN];
	unsigned long a2[MAX_NR_CHILDREN];
	unsigned long a3[MAX_NR_CHILDREN];
	unsigned long a4[MAX_NR_CHILDREN];
	unsigned long a5[MAX_NR_CHILDREN];
	unsigned long a6[MAX_NR_CHILDREN];

	int current_fd;
	unsigned int fd_lifetime;

	/* various flags. */
	bool do32bit[MAX_NR_CHILDREN];
	bool do_make_it_fail;
	bool need_reseed;
	enum exit_reasons exit_reason;

	/* locks */
	volatile unsigned char regenerating;
	volatile unsigned char reaper_lock;
};
extern struct shm_s *shm;

#define SHM_OK 0
#define SHM_CORRUPT 1

#endif	/* _SHM_H */
