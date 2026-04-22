#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

struct childdata;
struct syscallrecord;

/*
 * Per-child rolling history of recently completed syscalls.  Cheaper than
 * a full struct syscallrecord (no prebuffer/postbuffer text), so we keep
 * many more entries per child without bloating shared memory.
 *
 * Drained on __BUG() entry to recover the syscall(s) the offending child
 * had been running just before the assertion fired.  The motivating case
 * is parent-side list/fd_event_drain corruption caused by a child wild
 * write hundreds of syscalls earlier: the existing minicorpus retains
 * coverage-productive args but not raw recent history, and the smaller
 * 16-entry child_syscall_ring fires only on kernel taint, not on a
 * trinity-internal __BUG.  64 entries spans the few hundred syscalls
 * that typically run between a corruption-causing write and the parent's
 * eventual notice.
 *
 * SIZE must be a power of two so the head index reduction is a single AND.
 */
#define PRE_CRASH_RING_SIZE	64

struct pre_crash_entry {
	struct timespec ts;		/* CLOCK_MONOTONIC at syscall return. */
	unsigned long args[6];		/* argument values as the syscall saw them. */
	long retval;			/* return value the kernel reported. */
	unsigned int syscall_nr;	/* index into the syscall table. */
	int errno_post;			/* errno after return. */
	bool do32bit;			/* selects which table syscall_nr indexes. */
};

struct pre_crash_ring {
	struct pre_crash_entry entries[PRE_CRASH_RING_SIZE];
	/* Lock-free SPSC: only the owning child writes head, with a release
	 * store after the slot is fully populated.  Post-mortem readers do
	 * an acquire load to observe the matching slot intact. */
	_Atomic uint32_t head;
};

void pre_crash_ring_record(struct childdata *child,
			   const struct syscallrecord *rec,
			   const struct timespec *now);

void pre_crash_ring_dump(struct childdata *child);

void pre_crash_ring_dump_all(void);
