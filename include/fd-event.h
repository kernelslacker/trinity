#pragma once

#include <stdint.h>
#include "object-types.h"

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
	FD_EVENT_REGEN_REQUEST,	/* refill the pool of objtype */
	FD_EVENT_NEWSOCK,	/* child accept4'd a socket; parent adds it to the pool */
};

/*
 * For FD_EVENT_CLOSE the closed fd is in fd1.  For FD_EVENT_REGEN_REQUEST
 * fd1/fd2 are unused (-1) and only objtype is meaningful — the parent
 * runs that provider's open hook in its own context where add_object()
 * on OBJ_GLOBAL is allowed to mutate the pool.  For FD_EVENT_NEWSOCK
 * fd1 is the accepted fd, fd2 is the socket family, socktype and protocol
 * carry the remaining triplet fields; objtype is unused.
 */
struct fd_event {
	enum fd_event_type type;
	int fd1;		/* fd (FD_EVENT_CLOSE, FD_EVENT_NEWSOCK) */
	int fd2;		/* FD_EVENT_NEWSOCK: socket family */
	enum objecttype objtype;  /* FD_EVENT_REGEN_REQUEST: object type to regen */
	unsigned int socktype;	  /* FD_EVENT_NEWSOCK: socket type */
	unsigned int protocol;	  /* FD_EVENT_NEWSOCK: socket protocol */
};

struct fd_event_ring {
	/* Written by child (producer), read by parent (consumer). */
	_Atomic uint32_t head;

	/* Overflow counter — bumped by child on ring-full drops. */
	_Atomic uint32_t overflow;

	/* Padding to put producer and consumer fields on separate cache lines. */
	char __pad[56];

	/* Written by parent (consumer), read by child (producer). */
	_Atomic uint32_t tail;

	struct fd_event events[FD_EVENT_RING_SIZE];
};

void fd_event_ring_init(struct fd_event_ring *ring);

/*
 * Enqueue an fd event from child context.  Lock-free, returns false
 * if the ring is full (event is dropped).
 */
bool fd_event_enqueue(struct fd_event_ring *ring,
		      enum fd_event_type type,
		      int fd1, int fd2,
		      enum objecttype objtype,
		      unsigned int socktype, unsigned int protocol);

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
