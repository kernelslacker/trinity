#pragma once

#include <stdint.h>
#include "arch.h"
#include "child.h"
#include "exit.h"
#include "files.h"
#include "locks.h"
#include "net.h"
#include "stats.h"
#include "syscall.h"
#include "types.h"

struct io_uringobj;

void create_shm(void);
void init_shm(void);

/*
 * Toggle write protection on the shm struct page(s).  Used to bracket
 * parent-only writes so that stray pointer writes from fuzzing children
 * fault instead of silently corrupting shared state.
 */
void shm_set_writable(void);
void shm_set_readonly(void);

struct shm_s {
	char __padding[4096];

	/* Frequently updated by all children — own cache line. */
	struct stats_s stats __attribute__((aligned(64)));

	/* Global fd generation counter — bumped on every fd state change
	 * (create, close, dup).  Children compare against their cached
	 * copy to detect stale fds without fcntl(F_GETFD) probes. */
	uint32_t fd_generation __attribute__((aligned(64)));

	/* Written by main process — own cache line to avoid
	 * false sharing with child-written stats above. */
	unsigned int running_childs __attribute__((aligned(64)));

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

	/* io_uring ring with valid mappings, shared across children.
	 * Protected by objlock. */
	struct io_uringobj *mapped_ring;

	/* Contended child<>child locks — own cache line. */
	lock_t syscalltable_lock __attribute__((aligned(64)));
	lock_t objlock;
	lock_t buglock;

	/* various flags. */
	enum exit_reasons exit_reason;
	bool dont_make_it_fail;
	_Atomic bool spawn_no_more;
	_Atomic bool ready;
	bool postmortem_in_progress;

	/* global debug flag.
	 * This is in the shm so we can do things like gdb to the main pid,
	 * and have the children automatically take notice.
	 * This can be useful if for some reason we don't want to gdb to the child.
	 */
	bool debug;

	/* set to true if a child hits an EPERM/EINVAL trying to
	 * unshare(CLONE_NEWPID). Stored in shm so the flag propagates
	 * across fork() — a process-local static would be duplicated
	 * into each child's address space. */
	bool no_pidns;
};
extern struct shm_s *shm;
extern unsigned int shm_size;

/*
 * Global pointer to the children array.  Lives in normal data segment
 * (NOT in shm), so each forked process gets its own COW copy.  A stray
 * child write to this pointer corrupts only that one child's copy and
 * cannot zero out the pointer for parent or siblings.  The pointed-to
 * array is mprotected PROT_READ in init_shm() so its contents are
 * also protected.
 */
extern struct childdata **children;
