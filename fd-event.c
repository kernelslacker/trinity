/*
 * fd event ring buffer — lock-free SPSC queue for child-to-parent
 * fd state change reporting.
 *
 * Each child produces close events into its own ring.
 * The parent drains events and updates the global object pool.
 */

#include <inttypes.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "child.h"
#include "fd.h"
#include "fd-event.h"
#include "locks.h"
#include "objects.h"
#include "pids.h"
#include "shm.h"
#include "spsc-ring.h"
#include "trinity.h"
#include "utils.h"

void fd_event_ring_init(struct fd_event_ring *ring)
{
	memset(ring->events, 0, sizeof(ring->events));
	spsc_ring_init(&ring->base);
}

/*
 * Enqueue from child context.  Single-producer: only the child
 * writes head.  Returns false if the ring is full.
 */
bool fd_event_enqueue(struct fd_event_ring *ring,
		      enum fd_event_type type,
		      int fd1)
{
	struct fd_event ev = {
		.type = type,
		.fd1 = fd1,
	};

	if (ring == NULL)
		return false;

	return spsc_ring_try_enqueue(&ring->base, ring->events,
				     FD_EVENT_RING_SIZE, sizeof(ring->events[0]),
				     &ev);
}

/*
 * Bundle the three steps every child-side close path must perform
 * into a single call site so the order and the set stay enforced:
 * publish the close to the parent, evict the local fd_hash[]
 * snapshot, and sentinel-out the live_fds ring slot.  Mirrors the
 * sequence post_close has always run inline; future child-side
 * close paths should route through here rather than re-spelling
 * the three steps and risk drifting out of sync.
 *
 * fd_event_enqueue() already tolerates a NULL ring, so the only
 * precondition the helper imposes on the caller is a non-NULL
 * child -- the surrounding paths already gate on this_child().
 */
void notify_child_fd_closed(struct childdata *child, int fd)
{
	fd_event_enqueue(child->fd_event_ring, FD_EVENT_CLOSE, fd);
	fd_hash_remove_local(fd);
	child_fd_ring_remove(&child->live_fds, fd);
}

void notify_child_fd_closed_range(struct childdata *child, int lo, int hi)
{
	int fd;

	if (lo > hi)
		return;

	for (fd = lo; fd <= hi; fd++)
		fd_event_enqueue(child->fd_event_ring, FD_EVENT_CLOSE, fd);

	fd_hash_remove_local_range(lo, hi);
	child_fd_ring_remove_range(&child->live_fds, lo, hi);
}

/*
 * Validate a child-supplied event before acting on it.  Children run
 * hostile fuzzed workloads and have unfettered write access to their
 * own ring, so any field -- including the type tag -- can be arbitrary
 * garbage.  Only CLOSE is a valid type today; any other value is
 * either an out-of-range enum or a TOCTOU flip and is dropped.
 *
 * The caller passes a parent-local copy of the slot, not the shared
 * ring slot itself: see apply_slot() below for the TOCTOU rationale.
 */
static bool fd_event_payload_valid(const struct fd_event *ev)
{
	switch (ev->type) {
	case FD_EVENT_CLOSE:
		return ev->fd1 >= 0;
	default:
		return false;
	}
}

static void apply_slot(const void *p, void *ctx __unused__)
{
	/*
	 * spsc_ring_drain() hands us a pointer INTO the shared ring
	 * slot.  The producing child has unfettered write access to
	 * its own ring (see header comment above on the threat model),
	 * so any second read of a field is a TOCTOU window: the child
	 * can flip e.g. fd2 between fd_event_payload_valid()'s bound
	 * check and add_socket()'s use of it as an index into
	 * net_protocols[].  Snapshot the slot once into a parent-local
	 * struct here and operate exclusively on the local copy below;
	 * the shared slot is touched exactly once, on this line.
	 */
	struct fd_event ev = *(const struct fd_event *)p;
	bool corrupt = false;

	if (!fd_event_payload_valid(&ev)) {
		corrupt = true;
	} else {
		switch (ev.type) {
		case FD_EVENT_CLOSE: {
			/*
			 * Per-provider outstanding-fd gauge: look up the
			 * closing fd's objtype on the consumer side
			 * (parent owns parent_fd_hash exclusively, so no
			 * TOCTOU) and decrement before remove_object_by_fd
			 * destroys the entry.  add_object()'s fd_hash_insert
			 * success path bumped the same slot; a NULL lookup
			 * means the fd was never registered globally and
			 * has nothing to decrement.
			 */
			struct fd_hash_entry *fe = fd_hash_lookup(ev.fd1);

			if (fe != NULL && fe->type < MAX_OBJECT_TYPES)
				__atomic_fetch_sub(&shm->stats.fd_provider_outstanding[fe->type],
						   1, __ATOMIC_RELAXED);
			remove_object_by_fd(ev.fd1);
			break;
		}
		default:
			/* Defense in depth: payload_valid() already
			 * screened type on the local copy, so reaching
			 * this arm means the enum range expanded
			 * without payload_valid() being taught about
			 * it -- not a TOCTOU flip, since ev is local. */
			corrupt = true;
			break;
		}
	}

	if (corrupt) {
		output(0, "fd_event: dropping corrupt event (type=%u fd1=%d)\n",
		       (unsigned int)ev.type, ev.fd1);
		__atomic_add_fetch(&shm->stats.fd_event_payload_corrupt,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Drain all pending events from one child's ring.
 * Single-consumer: only the parent writes tail.
 */
unsigned int fd_event_drain(struct fd_event_ring *ring)
{
	uint64_t overflow = 0;
	uint32_t processed;

	if (ring == NULL)
		return 0;

	processed = spsc_ring_drain(&ring->base, ring->events,
				    FD_EVENT_RING_SIZE, sizeof(ring->events[0]),
				    apply_slot, NULL, &overflow);
	if (overflow > 0) {
		output(1, "fd_event: ring overflow, %" PRIu64 " events dropped\n",
		       overflow);
		__atomic_add_fetch(&shm->stats.fd_events_dropped, overflow,
				   __ATOMIC_RELAXED);
	}
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
}
