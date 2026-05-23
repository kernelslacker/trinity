#pragma once

#include <stdint.h>
#include "spsc-ring.h"

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
