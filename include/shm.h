#pragma once

#include <sys/time.h>
#include <sys/types.h>

#include <stdio.h>

#include "constants.h"
#include "exit.h"
#include "net.h"
#include "types.h"

void create_shm(void);
void create_shm_arrays(void);
void init_shm(void);

struct shm_s {
	unsigned long total_syscalls_done;
	unsigned long successes;
	unsigned long failures;
	unsigned long previous_count;
	unsigned long *child_syscall_count;

	unsigned long regenerate;
	unsigned int seed;
	unsigned int *seeds;
	unsigned int reseed_counter;

	//Indices of syscall in syscall table that are active. All indices shifted by +1. Empty index equals to 0.
	int active_syscalls32[MAX_NR_SYSCALL];
	int active_syscalls64[MAX_NR_SYSCALL];
	int active_syscalls[MAX_NR_SYSCALL];
	unsigned int nr_active_syscalls;
	unsigned int nr_active_32bit_syscalls;
	unsigned int nr_active_64bit_syscalls;

	pid_t mainpid;
	pid_t *pids;
	unsigned char *child_type;

	pid_t last_reaped;
	bool spawn_no_more;
	unsigned char *kill_count;

	unsigned int running_childs;
	struct timeval *tv;

	FILE **logfiles;

	int pipe_fds[MAX_PIPE_FDS*2];
	int file_fds[NR_FILE_FDS];		/* All children inherit these */
	int perf_fds[MAX_PERF_FDS];
	int epoll_fds[MAX_EPOLL_FDS];
	int eventfd_fds[MAX_EPOLL_FDS];

	struct socketinfo sockets[NR_SOCKET_FDS];

	/* state for the syscall currently in progress. */
	unsigned int *previous_syscallno;
	unsigned long *previous_a1;
	unsigned long *previous_a2;
	unsigned long *previous_a3;
	unsigned long *previous_a4;
	unsigned long *previous_a5;
	unsigned long *previous_a6;

	unsigned int *syscallno;	/* protected by syscall_lock */
	unsigned long *a1;
	unsigned long *a2;
	unsigned long *a3;
	unsigned long *a4;
	unsigned long *a5;
	unsigned long *a6;

	unsigned long *retval;

	unsigned long *scratch;

	int current_fd;
	unsigned int fd_lifetime;

	/* per-child mmaps */
	struct map **mappings;
	unsigned int *num_mappings;

	/* various flags. */
	bool *do32bit;			/* protected by syscall_lock */
	bool do_make_it_fail;
	bool need_reseed;
	enum exit_reasons exit_reason;

	/* locks */
	volatile unsigned char regenerating;
	volatile unsigned char reaper_lock;
	volatile unsigned char syscall_lock;

	bool ready;
};
extern struct shm_s *shm;

#define SHM_OK 0
#define SHM_CORRUPT 1
