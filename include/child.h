#pragma once

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include "types.h"
#include "edgepair.h"
#include "kcov.h"
#include "objects.h"
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
	uint32_t cached_fd_generation;	/* generation when current_fd was fetched */

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

	/* fd to /proc/self/fail-nth, opened once per child.  -1 means
	 * fault injection is unavailable on this kernel/config. */
	int fail_nth_fd;
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
bool drop_privs(struct childdata *child);
bool mmap_lifecycle(struct childdata *child);
bool mprotect_split(struct childdata *child);
bool mlock_pressure(struct childdata *child);
bool inode_spewer(struct childdata *child);
bool procfs_writer(struct childdata *child);
bool memory_pressure(struct childdata *child);
bool userns_fuzzer(struct childdata *child);
bool sched_cycler(struct childdata *child);
