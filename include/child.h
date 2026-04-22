#pragma once

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include "types.h"
#include "edgepair.h"
#include "kcov.h"
#include "objects.h"
#include "pre_crash_ring.h"
#include "syscall.h"

struct fd_event_ring;

/*
 * Circular ring of file descriptors returned by recent fd-creating syscalls.
 * Used to bias ARG_FD generation toward fds that are known to be open.
 */
#define CHILD_FD_RING_SIZE 16

struct child_fd_ring {
	int fds[CHILD_FD_RING_SIZE];
	unsigned int head;
};

/*
 * Per-child ring of recently completed syscall records.  The owning child
 * is the sole producer; the parent reads the ring in post-mortem context
 * to assemble a chronological fleet-wide trace of what was running just
 * before the kernel taint flag flipped.  Lock-free SPSC: producer issues
 * a release-store of head after writing the slot; consumer issues an
 * acquire-load of head before reading slots.  Size must be a power of 2.
 */
#define CHILD_SYSCALL_RING_SIZE 16

struct child_syscall_ring {
	struct syscallrecord recent[CHILD_SYSCALL_RING_SIZE];
	_Atomic uint32_t head;
};

enum child_op_type {
	CHILD_OP_SYSCALL = 0,	/* default: fuzz random syscalls */
	CHILD_OP_MMAP_LIFECYCLE,
	CHILD_OP_MPROTECT_SPLIT,
	CHILD_OP_MLOCK_PRESSURE,
	CHILD_OP_INODE_SPEWER,
	CHILD_OP_PROCFS_WRITER,
	CHILD_OP_MEMORY_PRESSURE,
	CHILD_OP_USERNS_FUZZER,
	CHILD_OP_SCHED_CYCLER,
	CHILD_OP_BARRIER_RACER,
	CHILD_OP_GENETLINK_FUZZER,
	CHILD_OP_PERF_CHAINS,
	CHILD_OP_TRACEFS_FUZZER,
	CHILD_OP_BPF_LIFECYCLE,
	CHILD_OP_FAULT_INJECTOR,
	CHILD_OP_RECIPE_RUNNER,
	CHILD_OP_IOURING_RECIPES,
	CHILD_OP_FD_STRESS,
	CHILD_OP_REFCOUNT_AUDITOR,
	CHILD_OP_FS_LIFECYCLE,
	CHILD_OP_SIGNAL_STORM,
	NR_CHILD_OP_TYPES,
};

struct childdata {
	/* The actual syscall records each child uses. */
	struct syscallrecord syscall;

	/* Per-child KCOV state (fd + trace buffer). */
	struct kcov_child kcov;

	struct objhead objects[MAX_OBJECT_TYPES];

	/* last time the child made progress. */
	struct timespec tp;
	unsigned long op_nr;

	/* Per-child syscall counter, batch-flushed to shm->stats.op_count
	 * every LOCAL_OP_FLUSH_BATCH ops to avoid contending one cache line
	 * across all children. Aggregated by the parent when an exact total
	 * is needed. */
	unsigned long local_op_count;

	unsigned int seed;

	unsigned int num;

	/* Last syscall group executed, for group biasing. */
	unsigned int last_group;

	/* Last syscall number executed, for edge-pair tracking. */
	unsigned int last_syscall_nr;

	/* per-child fd caching to avoid cross-child races */
	int current_fd;
	unsigned int fd_lifetime;
	/* Per-slot generation snapshot from current_fd's fd_hash entry,
	 * taken when the fd was fetched.  A mismatch on the next iteration
	 * indicates the slot was emptied or the fd number was recycled
	 * onto a fresh object; either way the cached fd is no longer
	 * trustworthy. */
	uint32_t cached_fd_generation;

	/* Ring buffer for reporting fd events to the parent.
	 * Allocated in shared memory, one per child. */
	struct fd_event_ring *fd_event_ring;

	/* FD leak instrumentation: count fds created and closed by
	 * this child's syscalls, with per-group breakdown.
	 * On child exit, if fd_created - fd_closed > threshold,
	 * we log which syscall groups are responsible. */
	unsigned long fd_created;
	unsigned long fd_closed;
	unsigned long fd_created_by_group[NR_GROUPS];

	unsigned char xcpu_count;

	unsigned char kill_count;

	bool dontkillme;	/* provide temporary protection from the reaper. */

	bool dropped_privs;

	enum child_op_type op_type;

	/* Stall detection state: consecutive alarm timeouts without progress. */
	unsigned int stall_count;
	unsigned int stall_last;

	/* Ring of fds returned by recent fd-creating syscalls.
	 * Consulted preferentially when generating ARG_FD arguments. */
	struct child_fd_ring live_fds;

	/* Ring of recently completed syscall records, drained by the parent
	 * during post-mortem to reconstruct a fleet-wide chronology. */
	struct child_syscall_ring syscall_ring;

	/* Compact rolling history of recently completed syscalls, drained
	 * on __BUG() to recover what this child was doing just before an
	 * assertion failure (most often a parent-side list/fd-event drain
	 * crash caused by a child wild write hundreds of syscalls back). */
	struct pre_crash_ring pre_crash;

	/* fd to /proc/self/fail-nth, opened once per child.  -1 means
	 * fault injection is unavailable on this kernel/config. */
	int fail_nth_fd;

	/* Name of the recipe currently executing inside recipe_runner(),
	 * or NULL when no recipe is in flight.  Read by post-mortem to
	 * attribute a kernel taint to a specific multi-syscall sequence. */
	const char *current_recipe_name;
};

extern unsigned int max_children;

struct childdata * this_child(void);

void clean_childdata(struct childdata *child);

void child_fd_ring_push(struct child_fd_ring *ring, int fd);

void child_syscall_ring_push(struct child_syscall_ring *ring,
			     const struct syscallrecord *rec);

void init_child_mappings(void);

void child_process(struct childdata *child, int childno);

void set_dontkillme(struct childdata *child, bool state);

void reap_child(struct childdata *child, int childno);

/* Childops */
bool random_syscall(struct childdata *child);
bool random_syscall_step(struct childdata *child,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new);
struct chain_step;
bool replay_syscall_step(struct childdata *child,
			 const struct chain_step *saved,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new);
bool drop_privs(struct childdata *child);
bool mmap_lifecycle(struct childdata *child);
bool mprotect_split(struct childdata *child);
bool mlock_pressure(struct childdata *child);
bool inode_spewer(struct childdata *child);
void inode_spewer_cleanup(void);
void inode_spewer_reap(pid_t pid);
bool procfs_writer(struct childdata *child);
void procfs_writer_init(void);
bool memory_pressure(struct childdata *child);
bool userns_fuzzer(struct childdata *child);
bool sched_cycler(struct childdata *child);
bool barrier_racer(struct childdata *child);
bool genetlink_fuzzer(struct childdata *child);
bool perf_event_chains(struct childdata *child);
bool tracefs_fuzzer(struct childdata *child);
bool bpf_lifecycle(struct childdata *child);
bool fault_injector(struct childdata *child);
bool recipe_runner(struct childdata *child);
bool iouring_recipes(struct childdata *child);
bool fd_stress(struct childdata *child);
bool refcount_auditor(struct childdata *child);
bool fs_lifecycle(struct childdata *child);
bool signal_storm(struct childdata *child);
