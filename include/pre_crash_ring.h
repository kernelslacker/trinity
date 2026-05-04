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

/*
 * Three event kinds share the ring so the post-mortem reader sees a single
 * chronologically-ordered stream.  SYSCALL slots populate every field
 * normally; TAINT slots reuse the existing fields to encode the taint
 * delta context (see pre_crash_ring_record_taint() for the encoding); CANARY
 * slots encode the syscallrecord wholesale-stomp event detected by the
 * post-handler canary check (see pre_crash_ring_record_canary() for the
 * encoding) so we don't need to grow the per-entry footprint just for new
 * watcher kinds.
 */
enum pre_crash_kind {
	PRE_CRASH_KIND_SYSCALL = 0,
	PRE_CRASH_KIND_TAINT,
	PRE_CRASH_KIND_CANARY,
};

struct pre_crash_entry {
	struct timespec ts;		/* CLOCK_MONOTONIC at event time. */
	unsigned long args[6];		/* SYSCALL: argument values as the syscall saw them.
					 * TAINT: args[0]=delta mask (XOR), args[1]=new tainted mask,
					 *        args[2]=op_type, args[3]=op_nr, args[4..5] unused. */
	long retval;			/* SYSCALL: return value the kernel reported. TAINT: 0. */
	unsigned int syscall_nr;	/* SYSCALL: index into the syscall table. TAINT: 0. */
	int errno_post;			/* SYSCALL: errno after return. TAINT: 0. */
	bool do32bit;			/* SYSCALL: selects which table syscall_nr indexes. TAINT: false. */
	uint8_t kind;			/* enum pre_crash_kind. */
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

/*
 * Push a soft-taint context entry: a /proc/sys/kernel/tainted bit
 * transition was observed across a non-syscall childop dispatch.  delta
 * is the XOR of the pre/post masks (which bits flipped), tainted_now is
 * the post-dispatch mask, op_type/op_nr identify the offending dispatch.
 * Lock-free SPSC same as the syscall path.
 */
void pre_crash_ring_record_taint(struct childdata *child,
				 unsigned long delta,
				 unsigned long tainted_now,
				 unsigned int op_type,
				 unsigned long op_nr);

/*
 * Push a wholesale-stomp context entry: handle_syscall_ret() observed
 * rec->_canary != REC_CANARY_MAGIC, meaning the entire syscallrecord
 * was rewritten between BEFORE and AFTER.  observed is the canary value
 * actually read (gives a hint at the clobber pattern: NUL-bytes →
 * value-result memset, ASCII → string write, pointer-shaped → struct
 * embedded pointer, etc.); the rec's nominal a1..a6 / nr / retval at the
 * moment of detection are preserved alongside so post-mortem can tell
 * which call was running when the stomp landed (the values themselves
 * are no longer trustworthy but the syscall_nr usually survives).
 * Lock-free SPSC same as the syscall path.
 */
void pre_crash_ring_record_canary(struct childdata *child,
				  const struct syscallrecord *rec,
				  uint64_t observed);

void pre_crash_ring_dump(struct childdata *child);

void pre_crash_ring_dump_all(void);
