#pragma once

#include <stdint.h>
#include "spsc-ring.h"

struct childdata;

/*
 * Lock-free single-producer single-consumer ring buffer for reporting
 * fd state changes from child processes to the parent.
 *
 * Each child gets its own ring in shared memory.  The child is the sole
 * producer (writes head); the parent is the sole consumer (writes tail).
 * No locks required — just atomic load/store with acquire/release.
 *
 * Overflow policy: drop the event silently.  Stale fd detection via
 * the generation counter remains as a backstop, so dropped events
 * just mean slightly delayed pool updates.
 */

#define FD_EVENT_RING_SIZE 1024	/* must be power of 2 */

enum fd_event_type {
	FD_EVENT_CLOSE,		/* child closed this fd */
	FD_EVENT_EVICT,		/* parent is evicting a stale slot whose fd
				 * may still be valid in a sibling child */
	FD_EVENT_CLOSE_RANGE,	/* child closed a contiguous fd range
				 * [fd1, fd2]; one event per bulk close
				 * to keep close_range() from overflowing
				 * the ring */
};

/*
 * CLOSE and EVICT carry a single fd in fd1 (fd2 unused) and differ only
 * in semantics: CLOSE means a child genuinely closed the fd, EVICT means
 * the parent watchdog is expiring a stale pool slot whose fd may still
 * be live in a sibling.  The drain handler treats them identically for
 * pool bookkeeping but bumps separate counters so we can measure how
 * often each path fires.
 *
 * CLOSE_RANGE carries a contiguous closed range in [fd1, fd2] so a
 * single close_range() bulk close enqueues one event instead of N --
 * a child closing a wide span no longer overflows FD_EVENT_RING_SIZE.
 * The drain loops the range and calls remove_object_by_fd() per fd
 * (cheap if the fd is not tracked).
 */
struct fd_event {
	enum fd_event_type type;
	int fd1;		/* CLOSE/EVICT: the fd; CLOSE_RANGE: lo */
	int fd2;		/* CLOSE_RANGE: hi; unused otherwise */
};

struct fd_event_ring {
	struct spsc_ring base;
	struct fd_event events[FD_EVENT_RING_SIZE];
};

void fd_event_ring_init(struct fd_event_ring *ring);

/*
 * Enqueue an fd event from child context.  Lock-free, returns false
 * if the ring is full (event is dropped).
 */
bool fd_event_enqueue(struct fd_event_ring *ring,
		      enum fd_event_type type,
		      int fd1);

/*
 * Range variant: enqueue a single FD_EVENT_CLOSE_RANGE carrying
 * [lo, hi] for bulk close_range()-style closes.  Returns false if
 * the ring is full or `hi < lo`.
 */
bool fd_event_enqueue_range(struct fd_event_ring *ring, int lo, int hi);

/*
 * Drain all pending events from a child's ring, calling the
 * appropriate object pool update for each.  Called from parent context.
 * Returns the number of events processed.
 */
unsigned int fd_event_drain(struct fd_event_ring *ring);

/*
 * Drain events from all children's rings.  Convenience wrapper
 * called from the parent main loop.
 */
void fd_event_drain_all(void);

/*
 * Notify the framework that the given child has closed `fd`.  Bundles
 * the three steps every child-side close path must perform so the
 * order and the set stay enforced at the call site:
 *
 *   1. enqueue FD_EVENT_CLOSE so the parent eventually retires the
 *      pooled object,
 *   2. evict the fd from this child's fd_hash[] snapshot so
 *      get_random_fd() / get_typed_fd() stop handing the dead fd
 *      back out before the parent drains the event,
 *   3. sentinel-out the fd in this child's live_fds ring so the next
 *      arg-generation pick doesn't burn an fcntl() on a known-dead
 *      slot.
 *
 * Child context only -- caller must ensure `child` is non-NULL.
 */
void notify_child_fd_closed(struct childdata *child, int fd);

/*
 * Range variant of notify_child_fd_closed for close_range()-style
 * bulk closes.  Enqueues one FD_EVENT_CLOSE per fd in [lo, hi],
 * evicts the whole range from fd_hash[] and the live_fds ring in
 * one pass each.  Child context only; caller must ensure `child`
 * is non-NULL.
 */
void notify_child_fd_closed_range(struct childdata *child, int lo, int hi);
