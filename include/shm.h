#pragma once

#include "arch.h"
#include "child.h"
#include "exit.h"
#include "files.h"
#include "locks.h"
#include "net.h"
#include "stats.h"
#include "syscall.h"
#include "types.h"

void create_shm(void);
void init_shm(void);

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
	/* generic object cache*/
	struct objhead global_objects[MAX_OBJECT_TYPES];

	/* file descriptor info */
	int current_fd;
	unsigned int fd_lifetime;

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

	/* set to true if a child hits an EPERM trying to unshare() */
	bool unshare_perm_err;
};
extern struct shm_s *shm;
extern unsigned int shm_size;
