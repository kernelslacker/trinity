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
	FD_EVENT_CLOSE,		/* fd was closed */
};

/*
 * Only CLOSE is a valid event type today; fd1 carries the closed fd.
 * The struct intentionally has no other payload — see commit history
 * for the NEWSOCK publish path that was removed (post-fork accepted
 * fds live only in the child's fd table and cannot be published to
 * the parent's pool).
 */
struct fd_event {
	enum fd_event_type type;
	int fd1;		/* closed fd */
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
