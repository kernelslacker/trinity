/*
 * fd event ring buffer — lock-free SPSC queue for child-to-parent
 * fd state change reporting.
 *
 * Each child produces events (dup, close) into its own ring.
 * The parent drains events and updates the global object pool.
 */

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "fd.h"
#include "fd-event.h"
#include "locks.h"
#include "objects.h"
#include "pids.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

void fd_event_ring_init(struct fd_event_ring *ring)
{
	memset(ring, 0, sizeof(*ring));
	atomic_store_explicit(&ring->head, 0, memory_order_relaxed);
	atomic_store_explicit(&ring->tail, 0, memory_order_relaxed);
	atomic_store_explicit(&ring->overflow, 0, memory_order_relaxed);
}

/*
 * Enqueue from child context.  Single-producer: only the child
 * writes head.  Returns false if the ring is full.
 */
bool fd_event_enqueue(struct fd_event_ring *ring,
		      enum fd_event_type type,
		      int fd1, int fd2,
		      enum objecttype objtype)
{
	uint32_t head, tail, next;

	head = atomic_load_explicit(&ring->head, memory_order_relaxed);
	head &= (FD_EVENT_RING_SIZE - 1);
	tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
	tail &= (FD_EVENT_RING_SIZE - 1);

	next = (head + 1) & (FD_EVENT_RING_SIZE - 1);
	if (next == tail) {
		/* Ring full — drop the event.  Stale detection is backstop. */
		atomic_fetch_add_explicit(&ring->overflow, 1,
					  memory_order_relaxed);
		return false;
	}

	ring->events[head].type = type;
	ring->events[head].fd1 = fd1;
	ring->events[head].fd2 = fd2;
	ring->events[head].objtype = objtype;

	/* Ensure the event data is visible before advancing head. */
	atomic_store_explicit(&ring->head, next, memory_order_release);
	return true;
}

/*
 * Drain all pending events from one child's ring.
 * Single-consumer: only the parent writes tail.
 */
unsigned int fd_event_drain(struct fd_event_ring *ring)
{
	uint32_t head, tail, overflow;
	unsigned int processed = 0;

	/* Check and reset overflow counter. */
	overflow = atomic_exchange_explicit(&ring->overflow, 0,
					    memory_order_relaxed);
	if (overflow > 0) {
		output(1, "fd_event: ring overflow, %u events dropped\n",
		       overflow);
		__atomic_add_fetch(&shm->stats.fd_events_dropped, overflow,
				   __ATOMIC_RELAXED);
	}

	tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
	tail &= (FD_EVENT_RING_SIZE - 1);
	/* Acquire pairs with child's release-store of head. */
	head = atomic_load_explicit(&ring->head, memory_order_acquire);
	head &= (FD_EVENT_RING_SIZE - 1);

	while (tail != head) {
		struct fd_event *ev = &ring->events[tail];

		switch (ev->type) {
		case FD_EVENT_DUP:
			/* The dup'd fd exists only in the child's fd table
			 * (children have independent fd tables after fork).
			 * Don't create global objects for fds the parent
			 * doesn't own — the destructor would close() an
			 * fd that either doesn't exist in the parent or
			 * belongs to something else entirely. */
			break;

		case FD_EVENT_CLOSE:
			remove_object_by_fd(ev->fd1);
			break;

		case FD_EVENT_CREATED:
			/* Like DUP, the new fd exists only in the child.
			 * Adding it to OBJ_GLOBAL would create a phantom
			 * object whose destructor closes an unrelated
			 * parent fd. */
			break;
		}

		tail = (tail + 1) & (FD_EVENT_RING_SIZE - 1);
		processed++;
	}

	/* Release-store so the child sees the updated tail. */
	atomic_store_explicit(&ring->tail, tail, memory_order_release);
	return processed;
}

/*
 * Drain events from all children's rings.
 * Called from the parent main loop (handle_children / watchdog path).
 */
void fd_event_drain_all(void)
{
	unsigned int i;
	unsigned int total = 0;
	bool was_protected;

	/* Bracket the entire drain with a single thaw/refreeze pair.
	 * Each remove_object_by_fd() call would otherwise issue O(N)
	 * mprotect syscalls per event; with high fd churn that adds
	 * up to thousands of mprotects per drain. Lift once, drain,
	 * refreeze. */
	was_protected = globals_are_protected();
	if (was_protected)
		thaw_global_objects();

	for_each_child(i) {
		struct childdata *child;
		struct fd_event_ring *ring;

		/*
		 * Snapshot the child pointer with an acquire load.
		 * children[i] lives in shared memory (the array itself
		 * is mprotected PROT_READ after init, but we still want
		 * a stable read here against compiler reordering).
		 */
		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;

		ring = __atomic_load_n(&child->fd_event_ring, __ATOMIC_ACQUIRE);
		if (ring == NULL)
			continue;

		total += fd_event_drain(ring);
	}

	if (total > 0)
		__atomic_add_fetch(&shm->stats.fd_events_processed, total,
				   __ATOMIC_RELAXED);

	if (was_protected)
		freeze_global_objects();
}
