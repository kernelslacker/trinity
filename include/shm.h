#pragma once

#include "arch.h"
#include "child.h"
#include "drm_fds.h"
#include "epoll.h"
#include "eventfd.h"
#include "exit.h"
#include "files.h"
#include "inotify.h"
#include "locks.h"
#include "memfd.h"
#include "net.h"
#include "pipes.h"
#include "perf.h"
#include "stats.h"
#include "syscall.h"
#include "testfile.h"
#include "timerfd.h"
#include "types.h"

void create_shm(void);
void init_shm(void);

void shm_ro(void);
void shm_rw(void);

struct shm_s {
	struct childdata **children;

	struct stats_s stats;

	unsigned int running_childs;

	/* rng related state */
	unsigned int seed;

	/* Indices of syscall in syscall table that are active.
	 * All indices shifted by +1. Empty index equals to 0.
	 *
	 * 'active_syscalls' is only used on uniarch. The other two
	 * are only used on biarch. */
	int active_syscalls32[MAX_NR_SYSCALL];
	int active_syscalls64[MAX_NR_SYSCALL];
	int active_syscalls[MAX_NR_SYSCALL];
	unsigned int nr_active_syscalls;
	unsigned int nr_active_32bit_syscalls;
	unsigned int nr_active_64bit_syscalls;

#ifdef ARCH_IS_BIARCH
	/* Check that 32bit emulation is available. */
	unsigned int syscalls32_succeeded;
	unsigned int syscalls32_attempted;
#endif

	/* pids */
	pid_t mainpid;
	pid_t last_reaped;

	/* file descriptors, created in main, inherited in children */
	int pipe_fds[MAX_PIPE_FDS];
	int file_fds[NR_FILE_FDS];
	int perf_fds[MAX_PERF_FDS];
	int epoll_fds[MAX_EPOLL_FDS];
	int eventfd_fds[MAX_EVENTFD_FDS];
	int timerfd_fds[MAX_TIMERFD_FDS];
	int testfile_fds[MAX_TESTFILE_FDS];
	int memfd_fds[MAX_MEMFD_FDS];
	int drm_fds[MAX_DRM_FDS];
	int inotify_fds[MAX_INOTIFY_FDS];
	struct socketinfo sockets[NR_SOCKET_FDS];
	int current_fd;
	unsigned int fd_lifetime;

	/* main<>watchdog mutex, for reap_child()
	 *  provides exclusion so they don't both try at the same time. */
	lock_t reaper_lock;

	/* to protect from multiple child processes from
	 * trying to disable the same syscall at the same time. */
	lock_t syscalltable_lock;

	/* child<>child mutex, used so only one child spews debug output */
	lock_t buglock;

	/* various flags. */
	enum exit_reasons exit_reason;
	bool dont_make_it_fail;
	bool spawn_no_more;
	bool ready;
	bool postmortem_in_progress;

	/* global debug flag.
	 * This is in the shm so we can do things like gdb to the main pid,
	 * and have the children automatically take notice.
	 * This can be useful if for some reason we don't want to gdb to the child.
	 */
	bool debug;
};
extern struct shm_s *shm;
