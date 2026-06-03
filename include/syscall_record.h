#pragma once

#include "syscall.h"

/*
 * Sequence-counter publish/snapshot helpers for diagnostic readers
 * that skip rec->lock.  Writer brackets every coherent publish with
 * srec_publish_begin (odd sequence) / srec_publish_end (even sequence,
 * release).  Reader spin-copies fields between two acquire-loads of
 * rec->seq and accepts only when both reads are equal AND even.
 * Bounded retry; on give-up, reader skips the snapshot.
 *
 * The publish brackets are self-sufficient: srec_publish_begin's
 * release-store + acquire-fence prevents subsequent field writes
 * from being hoisted above the odd marker, and srec_publish_end's
 * release-store publishes those writes to readers.  Writers MAY
 * drop rec->lock provided all coherent field writes sit between
 * the brackets -- the brackets ARE the writer-side ordering anchor,
 * not the lock.  Readers that still take the lock for non-snapshot
 * reads keep working unchanged.
 */

/*
 * srec_publish_begin -- mark an odd sequence to signal "mutation in
 * progress".  The release-store on seq orders prior writes against
 * the marker; the trailing acquire-fence prevents the compiler (and
 * the CPU on weak-ordering architectures) from hoisting subsequent
 * field writes above the marker.  Together these replace the lock
 * acquire as the writer-side ordering anchor, so writer sites are
 * free to drop the surrounding rec->lock.
 */
static inline void srec_publish_begin(struct syscallrecord *rec)
{
	uint32_t s = __atomic_load_n(&rec->seq, __ATOMIC_RELAXED);

	__atomic_store_n(&rec->seq, s | 1U, __ATOMIC_RELEASE);
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
}

/*
 * srec_publish_end -- force even (bumped by at least 1 from the begin's
 * odd value) with a release-store so any reader that observes the new
 * even seq also sees every field write that happened between begin/end.
 */
static inline void srec_publish_end(struct syscallrecord *rec)
{
	uint32_t s = __atomic_load_n(&rec->seq, __ATOMIC_RELAXED);

	__atomic_store_n(&rec->seq, (s + 1U) & ~1U, __ATOMIC_RELEASE);
}

#define SREC_SNAPSHOT_RETRIES	4

/*
 * SREC_SNAPSHOT(rec, copy_block, got_out)
 *
 * Reader-side counterpart.  Caller supplies a block that copies the
 * fields it cares about out of (rec); the macro brackets the block
 * with two acquire-loads of rec->seq, retries on torn or in-progress
 * reads up to SREC_SNAPSHOT_RETRIES times, and stamps got_out true
 * iff a coherent snapshot was captured.
 *
 * Defined as a macro because the field set wanted varies per callsite
 * (stuck_syscall_info wants nr/do32bit/state/args/retval; the picker
 * triples want only nr/do32bit; is_child_making_progress already uses
 * a single-field atomic state load and does not need a snapshot at
 * all).
 *
 * Usage:
 *   bool got;
 *   unsigned int snap_nr;
 *   bool snap_do32;
 *   SREC_SNAPSHOT(rec, {
 *           snap_nr = rec->nr;
 *           snap_do32 = rec->do32bit;
 *   }, got);
 *   if (got) { ... use snapshot ... }
 */
#define SREC_SNAPSHOT(rec, copy_block, got_out) do {			\
	int _attempts = 0;						\
	uint32_t _pre, _post;						\
	(got_out) = false;						\
	while (_attempts < SREC_SNAPSHOT_RETRIES) {			\
		_pre = __atomic_load_n(&(rec)->seq, __ATOMIC_ACQUIRE);	\
		if (_pre & 1U) { _attempts++; continue; }		\
		do { copy_block } while (0);				\
		__atomic_thread_fence(__ATOMIC_ACQUIRE);		\
		_post = __atomic_load_n(&(rec)->seq, __ATOMIC_ACQUIRE);	\
		if (_pre == _post) { (got_out) = true; break; }		\
		_attempts++;						\
	}								\
} while (0)
