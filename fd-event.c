/*
 * fd event ring buffer — lock-free SPSC queue for child-to-parent
 * fd state change reporting.
 *
 * Each child produces close events into its own ring.
 * The parent drains events and updates the global object pool.
 */

#include <stdatomic.h>
#include <stdint.h>
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
		      enum objecttype objtype,
		      unsigned int socktype, unsigned int protocol)
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
	ring->events[head].socktype = socktype;
	ring->events[head].protocol = protocol;

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
		case FD_EVENT_CLOSE:
			remove_object_by_fd(ev->fd1);
			break;
		case FD_EVENT_REGEN_REQUEST:
			/* Clear the rate-limit slot first so any child
			 * that races with us still gets to enqueue a
			 * follow-up request rather than silently
			 * dropping it. */
			atomic_store_explicit(
				&shm->fd_regen_pending[ev->objtype], 0,
				memory_order_relaxed);
			try_regenerate_fd(ev->objtype);
			break;
		case FD_EVENT_NEWSOCK: {
			struct object *obj;

			/* add_socket() owns the fd on failure: on shared-heap
			 * exhaustion it close()s the fd before returning NULL.
			 * Capture the return so we don't silently treat a
			 * failed allocation as a successful publish.  Same
			 * hazard as the open_socket() call site fixed in
			 * commit 5373a93f1782. */
			obj = add_socket(ev->fd1, (unsigned int)ev->fd2,
					 ev->socktype, ev->protocol);
			if (obj == NULL)
				output(1, "fd_event: NEWSOCK add_socket() failed for fd %d (heap exhausted?)\n",
				       ev->fd1);
			break;
		}
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

		/*
		 * Sanity-check the ring pointer before dereferencing it.
		 * A D-state zombie waking after its slot was recycled can
		 * write a wild pointer here.  We saw 0x9c000000890000 in
		 * the wild: bit 47 set but bits 48-63 clear, which is
		 * non-canonical on x86-64.  Catch that pattern and any
		 * obviously low address rather than taking a SIGSEGV.
		 */
		{
			uintptr_t raddr = (uintptr_t)ring;
			uintptr_t top = raddr >> 47;

			if (raddr < 0x10000 ||
			    (top != 0 && top != 0x1ffff)) {
				output(0, "fd_event: child[%u] ring pointer %p is non-canonical, skipping\n",
				       i, ring);
				__atomic_add_fetch(&shm->stats.fd_event_ring_corrupted, 1,
						   __ATOMIC_RELAXED);
				continue;
			}
		}

		/*
		 * Canary check: compare the live pointer against the
		 * known-good value captured at init time.  A mismatch
		 * means the pointer field was overwritten after init
		 * (e.g. a stray write from a recycled child slot).
		 * Use the expected pointer for the drain so fuzzing can
		 * continue, but only after it passes the same sanity
		 * check we applied to the live pointer above.
		 */
		if (ring != expected_fd_event_rings[i]) {
			struct fd_event_ring *expected = expected_fd_event_rings[i];
			uintptr_t eaddr = (uintptr_t)expected;
			uintptr_t etop = eaddr >> 47;

			output(0, "fd_event: child[%u] ring pointer %p overwritten (expected %p)\n",
			       i, ring, expected);
			__atomic_add_fetch(&shm->stats.fd_event_ring_overwritten, 1,
					   __ATOMIC_RELAXED);

			if (eaddr < 0x10000 ||
			    (etop != 0 && etop != 0x1ffff)) {
				output(0, "fd_event: child[%u] expected ring %p also non-canonical, skipping\n",
				       i, expected);
				continue;
			}
			ring = expected;
		}

		total += fd_event_drain(ring);
	}

	if (total > 0)
		__atomic_add_fetch(&shm->stats.fd_events_processed, total,
				   __ATOMIC_RELAXED);

	if (was_protected)
		freeze_global_objects();
}
