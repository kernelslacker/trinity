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
		.fd2 = 0,
	};
	bool ok;

	if (ring == NULL)
		return false;

	ok = spsc_ring_try_enqueue(&ring->base, ring->events,
				   FD_EVENT_RING_SIZE, sizeof(ring->events[0]),
				   &ev);
	if (!ok) {
		/* Ring-full failure split by producer
		 * type.  The existing fd_events_dropped is bumped by
		 * the consumer-side overflow detector (drain) and
		 * aggregates everything; this per-type split says
		 * which producer path drove the overflow.  Bumped
		 * under the existing per-call RELAXED shm->stats
		 * convention (every other counter in this file
		 * follows the same shape). */
		switch (type) {
		case FD_EVENT_CLOSE:
			__atomic_add_fetch(&shm->stats.fd.event_full_close,
					   1, __ATOMIC_RELAXED);
			break;
		case FD_EVENT_EVICT:
			__atomic_add_fetch(&shm->stats.fd.event_full_evict,
					   1, __ATOMIC_RELAXED);
			break;
		default:
			/* FD_EVENT_CLOSE_RANGE doesn't reach here
			 * (it has its own producer at
			 * fd_event_enqueue_range below) — defensive
			 * default for any future type added without
			 * a counter wired through. */
			break;
		}
	}
	return ok;
}

/*
 * Range enqueue.  Bulk close_range() callers route through here so a
 * wide span is published as one event rather than N FD_EVENT_CLOSEs
 * (which would overflow FD_EVENT_RING_SIZE for spans > 1024).
 */
bool fd_event_enqueue_range(struct fd_event_ring *ring, int lo, int hi)
{
	struct fd_event ev = {
		.type = FD_EVENT_CLOSE_RANGE,
		.fd1 = lo,
		.fd2 = hi,
	};
	bool ok;

	if (ring == NULL)
		return false;
	if (hi < lo)
		return false;

	ok = spsc_ring_try_enqueue(&ring->base, ring->events,
				   FD_EVENT_RING_SIZE, sizeof(ring->events[0]),
				   &ev);
	if (ok) {
		/* Producer-side close-range observability.
		 * length_sum / enqueued = avg fds collapsed per
		 * FD_EVENT_CLOSE_RANGE event, the compression ratio
		 * the range opcode buys over the per-fd
		 * FD_EVENT_CLOSE path. */
		__atomic_add_fetch(&shm->stats.fd.event_close_range_enqueued,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.fd.event_close_range_length_sum,
				   (unsigned long)(hi - lo + 1),
				   __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.fd.event_full_close_range,
				   1, __ATOMIC_RELAXED);
	}
	return ok;
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

/*
 * Range close.  Enqueue a single FD_EVENT_CLOSE_RANGE carrying
 * [lo, hi] instead of N FD_EVENT_CLOSEs: a wide close_range() must
 * not overflow FD_EVENT_RING_SIZE (1024) and drop events.  The parent
 * drain walks the range and calls remove_object_by_fd() per fd; lookup
 * misses are O(1), so unrelated fds in the span are cheap.
 */
void notify_child_fd_closed_range(struct childdata *child, int lo, int hi)
{
	if (lo > hi)
		return;

	fd_event_enqueue_range(child->fd_event_ring, lo, hi);

	fd_hash_remove_local_range(lo, hi);
	child_fd_ring_remove_range(&child->live_fds, lo, hi);
}

/*
 * Validate a child-supplied event before acting on it.  Children run
 * hostile fuzzed workloads and have unfettered write access to their
 * own ring, so any field -- including the type tag -- can be arbitrary
 * garbage.  CLOSE (child closed the fd) and EVICT (parent watchdog
 * expiring a stale pool slot) are the only valid types today; any
 * other value is either an out-of-range enum or a TOCTOU flip and is
 * dropped.
 *
 * The caller passes a parent-local copy of the slot, not the shared
 * ring slot itself: see apply_slot() below for the TOCTOU rationale.
 */
static bool fd_event_payload_valid(const struct fd_event *ev)
{
	switch (ev->type) {
	case FD_EVENT_CLOSE:
	case FD_EVENT_EVICT:
		return ev->fd1 >= 0;
	case FD_EVENT_CLOSE_RANGE:
		/* Bounds and ordering.  The drain clamps the upper end of
		 * the walk separately to bound CPU; this is the structural
		 * check before any walk happens. */
		return ev->fd1 >= 0 && ev->fd2 >= ev->fd1;
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
		case FD_EVENT_CLOSE:
		case FD_EVENT_EVICT:
			/*
			 * CLOSE and EVICT both retire the pooled object: a
			 * child either genuinely closed the fd (CLOSE) or the
			 * parent watchdog is expiring a stale slot whose fd
			 * may still be live in a sibling (EVICT).  Either
			 * way the parent wants the slot gone.  Bump separate
			 * counters so the two paths stay observable.
			 *
			 * Per-provider outstanding-fd gauge decrement lives
			 * in __destroy_object() (objects/registry.c) so it covers
			 * every fd-provider destruction path -- parent-side
			 * stuck-fd eviction, close/close_range post-handlers,
			 * and perf/kvm peer pre-closes all flow through that
			 * common point.  remove_object_by_fd() ultimately
			 * calls __destroy_object(), so each drain still
			 * pays the decrement exactly once.
			 */
			remove_object_by_fd(ev.fd1);
			if (ev.type == FD_EVENT_EVICT)
				__atomic_add_fetch(&shm->stats.fd_event_evict_count,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.fd_event_close_count,
						   1, __ATOMIC_RELAXED);
			break;
		case FD_EVENT_CLOSE_RANGE: {
			/*
			 * Bulk-close range from close_range().  Walk
			 * [fd1, fd2] and retire each fd; remove_object_by_fd()
			 * is a no-op for untracked fds, so a span that
			 * straddles trinity-tracked and disposable sandbox
			 * fds is fine.  Clamp the walk width as defence
			 * against a child stomping fd2 to a wild value past
			 * the payload_valid() snapshot -- the snapshot is on
			 * a parent-local copy so a TOCTOU flip can't reach
			 * here, but the clamp also bounds a kernel-accepted
			 * range that simply grew past what close_range.c's
			 * post handler would have clamped.  Match the same
			 * 1024 cap close_range.c uses on the producer side.
			 */
			int lo = ev.fd1;
			int hi = ev.fd2;
			int fd;

			if (hi - lo > 1024)
				hi = lo + 1024;

			for (fd = lo; fd <= hi; fd++)
				remove_object_by_fd(fd);

			__atomic_add_fetch(&shm->stats.fd_event_close_count,
					   1, __ATOMIC_RELAXED);
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
		__atomic_add_fetch(&shm->stats.fd.event_payload_corrupt,
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
				__atomic_add_fetch(&shm->stats.fd.event_ring_corrupted, 1,
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
			__atomic_add_fetch(&shm->stats.fd.event_ring_overwritten, 1,
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
