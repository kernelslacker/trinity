#pragma once

#include <stdatomic.h>
#include <stdint.h>
#include "arch.h"
#include "child.h"
#include "efault_cache.h"
#include "exit.h"
#include "files.h"
#include "locks.h"
#include "net.h"
#include "object-types.h"
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
	_Atomic unsigned int seed;

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

	/*
	 * Per-objecttype hint: a child enqueueing FD_EVENT_REGEN_REQUEST
	 * sets the slot to 1, the parent's drain loop clears it before
	 * running the regen.  Stops the ring filling up with duplicate
	 * regen hints when many children notice the same exhausted pool
	 * inside the same drain cycle.  A late-arriving request that
	 * happens after the parent clears just gets a fresh enqueue,
	 * so this is purely a hint, not a correctness gate.
	 */
	_Atomic uint8_t fd_regen_pending[MAX_OBJECT_TYPES];

	/* io_uring ring with valid mappings, shared across children.
	 * Init write uses RELEASE; child reads use ACQUIRE (lockless).
	 * Destructor nulls this under objlock. */
	struct io_uringobj *mapped_ring;

	/* AIO context seeded by init_aio_global_ctx() in the parent.
	 * Init write uses RELEASE; child reads use ACQUIRE (lockless). */
	unsigned long aio_ctx_cached;

	/* Contended child<>child locks — own cache line. */
	lock_t syscalltable_lock __attribute__((aligned(64)));
	lock_t objlock;
	lock_t buglock;

	/*
	 * Bump-pointer cursor into the shared obj heap (see
	 * alloc_shared_obj() in utils.c).  In shm so concurrent
	 * allocators across processes share one cursor — the heap is
	 * mmap'd MAP_SHARED before fork, but post-fork allocs need a
	 * cross-process view of "which slot is next".
	 */
	_Atomic size_t shared_obj_heap_used;

	/*
	 * Sibling cursor for the shared string heap (see
	 * alloc_shared_str() in utils.c).  Same shm-cursor argument as
	 * shared_obj_heap_used; kept in a separate slab so string and
	 * obj allocations don't crowd each other and so each pool's
	 * exhaustion message names the right pool.
	 */
	_Atomic size_t shared_str_heap_used;

	/*
	 * Per-bucket freelist heads for the shared obj and str heaps.
	 * NUM_SHM_FREELIST_BUCKETS fixed-size slots (8..1024 bytes, powers of
	 * two); allocations above 1024 bytes bypass the freelist and use the
	 * bump allocator directly.  Each head is a uintptr_t storing the
	 * address of the most-recently-freed slot in that bucket (0 = empty).
	 * The link to the next free slot is stored in the slot's own first
	 * sizeof(uintptr_t) bytes (safe because the slot is, by definition,
	 * not live when the link is written).  Manipulated by lock-free CAS in
	 * freelist_push/pop in utils.c.
	 */
#define NUM_SHM_FREELIST_BUCKETS 8
	_Atomic uintptr_t shared_obj_freelist[NUM_SHM_FREELIST_BUCKETS];
	_Atomic uintptr_t shared_str_freelist[NUM_SHM_FREELIST_BUCKETS];

	/* various flags. */
	enum exit_reasons exit_reason;
	_Atomic bool dont_make_it_fail;

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
	_Atomic bool no_pidns;

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

	/*
	 * EFAULT-probe cache for ioctl arg classification.  Open-addressing
	 * hashmap keyed on (group_idx, request); see ioctls/efault_cache.c
	 * for the slot encoding and the probing protocol.  Lives in shm so
	 * a verdict reached by one child is reused by all the others — the
	 * kernel's ioctl tables are global and the probe has side effects
	 * we want to amortise.  Zero-initialised by create_shm(); packed ==
	 * 0 is the empty-slot sentinel.
	 */
	_Atomic uint64_t ioctl_efault_cache[IOCTL_EFAULT_CACHE_SIZE];
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
