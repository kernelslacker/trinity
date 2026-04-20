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

struct shm_s {
	char __padding[4096];

	/* Frequently updated by all children — own cache line. */
	struct stats_s stats __attribute__((aligned(64)));

	/*
	 * fd→object hash table.  Lives in shm so children can read the
	 * per-slot generation counter the parent updates on every
	 * fd_table mutation.  Reads from children are unlocked; writes
	 * from the parent happen under shm->objlock.
	 */
	struct fd_hash_entry fd_hash[FD_HASH_SIZE] __attribute__((aligned(64)));
	unsigned int fd_hash_count;

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
	 * Init write uses RELEASE; child reads use ACQUIRE (lockless).
	 * Destructor nulls this under objlock. */
	struct io_uringobj *mapped_ring;

	/* Contended child<>child locks — own cache line. */
	lock_t syscalltable_lock __attribute__((aligned(64)));
	lock_t objlock;
	lock_t buglock;

	/* various flags. */
	enum exit_reasons exit_reason;
	bool dont_make_it_fail;

	/* Set to true once we detect that /proc/self/fail-nth can't be
	 * opened (kernel built without CONFIG_FAULT_INJECTION, etc.).
	 * Lives in shm so the flag propagates across fork(). */
	bool no_fail_nth;
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

	/* recipe_runner discovery latches: a recipe whose first invocation
	 * detects an absent kernel feature (ENOSYS, missing config) flips
	 * its slot here so siblings stop probing.  Indexed by the recipe's
	 * slot in the static catalog inside recipe-runner.c. */
	bool recipe_disabled[MAX_RECIPES];

	/* iouring_recipes discovery latches: mirrors recipe_disabled but
	 * scoped to the iouring-recipes childop catalog. */
	bool iouring_recipe_disabled[MAX_IOURING_RECIPES];

	/* Set to true once we confirm io_uring_setup returns ENOSYS.
	 * Avoids repeated failed probes from every child. */
	bool iouring_enosys;
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

/*
 * Canary copy of each child's fd_event_ring pointer, taken at init time
 * and stored in an alloc_shared_global() region so it is mprotected
 * PROT_READ before any child starts running.  fd_event_drain_all()
 * compares the live pointer against this array; a mismatch means the
 * pointer was overwritten after init, and we use the known-good value
 * to keep draining while logging the incident.
 */
extern struct fd_event_ring **expected_fd_event_rings;
