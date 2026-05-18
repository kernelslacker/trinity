/*
 * Per-child stats ring buffer + parent-side aggregate.
 *
 * Children produce stats deltas into their own ring (write-only-by-owner);
 * the parent drains every ring once per main_loop iteration and applies
 * the deltas to a parent-private struct stats_aggregate that lives in
 * MAP_PRIVATE memory invisible to the kernel.  The kernel can no longer
 * scribble those counters via a wild syscall arg pointer because the
 * authoritative copy is not at any kernel-visible address.
 *
 * The mirror page (struct stats_published) carries the small subset of
 * the aggregate that children also need to read -- currently just
 * fleet_op_count for the strategy rotation clock and the syscalls_todo
 * termination check.  Republished once per drain.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "child.h"
#include "pids.h"
#include "shm.h"
#include "spsc-ring.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

struct stats_aggregate parent_stats;
struct stats_published *shm_published;

void stats_ring_init(struct stats_ring *ring)
{
	memset(ring->slots, 0, sizeof(ring->slots));
	spsc_ring_init(&ring->base);
}

bool stats_ring_enqueue(struct stats_ring *ring, enum stats_field field,
			uint16_t aux, uint32_t delta)
{
	struct stats_ring_slot slot = {
		.field_id = (uint16_t)field,
		.aux = aux,
		.delta = delta,
		._reserved = 0,
	};

	if (ring == NULL)
		return false;

	return spsc_ring_try_enqueue(&ring->base, ring->slots, STATS_RING_SIZE,
				     sizeof(ring->slots[0]), &slot);
}

/*
 * Apply a single ring slot to parent_stats.  Validates the field_id /
 * aux combination before touching any array index -- children produce
 * hostile fuzzed workload and a wild value-result syscall buffer that
 * scribbled a slot can leave any field at any value.
 */
static void apply_slot(const void *p, void *ctx __unused__)
{
	const struct stats_ring_slot *s = p;
	enum stats_field field = (enum stats_field)s->field_id;
	uint16_t aux = s->aux;
	unsigned long delta = s->delta;

	switch (field) {
	case STATS_FIELD_OP_COUNT:
		parent_stats.op_count += delta;
		break;
	case STATS_FIELD_SUCCESSES:
		parent_stats.successes += delta;
		break;
	case STATS_FIELD_FAILURES:
		parent_stats.failures += delta;
		break;
	case STATS_FIELD_FAULT_INJECTED:
		parent_stats.fault_injected += delta;
		break;
	case STATS_FIELD_FAULT_CONSUMED:
		parent_stats.fault_consumed += delta;
		break;
	case STATS_FIELD_SHARED_BUFFER_REDIRECTED:
		parent_stats.shared_buffer_redirected += delta;
		break;
	case STATS_FIELD_LIBC_HEAP_REDIRECTED:
		parent_stats.libc_heap_redirected += delta;
		break;
	case STATS_FIELD_LIBC_HEAP_EMBEDDED_REDIRECTED:
		parent_stats.libc_heap_embedded_redirected += delta;
		break;
	case STATS_FIELD_RANGE_OVERLAPS_SHARED_REJECTS:
		parent_stats.range_overlaps_shared_rejects += delta;
		break;
	case STATS_FIELD_GET_WRITABLE_SCRIBBLED:
		parent_stats.get_writable_address_scribbled_slots_caught += delta;
		break;
	case STATS_FIELD_CHILDREN_RECYCLED_ON_STORM:
		parent_stats.children_recycled_on_storm += delta;
		break;
	case STATS_FIELD_UNSHARE_NEWNET_THROTTLED:
		parent_stats.unshare_newnet_throttled += delta;
		break;
	case STATS_FIELD_RANGE_REJECTS_PER_SYSCALL_64:
		if (aux < MAX_NR_SYSCALL)
			parent_stats.range_overlaps_shared_rejects_per_syscall_64[aux] += delta;
		break;
	case STATS_FIELD_RANGE_REJECTS_PER_SYSCALL_32:
		if (aux < MAX_NR_SYSCALL)
			parent_stats.range_overlaps_shared_rejects_per_syscall_32[aux] += delta;
		break;
	case STATS_FIELD_SYSCALL_CATEGORY_COUNT:
		if (aux < NR_SYSCAT)
			parent_stats.syscall_category_count[aux] += delta;
		break;
	case STATS_FIELD_POST_HANDLER_CORRUPT_PTR:
		parent_stats.post_handler_corrupt_ptr += delta;
		break;
	case STATS_FIELD_DEFERRED_FREE_REJECT:
		parent_stats.deferred_free_reject += delta;
		break;
	case STATS_FIELD_SNAPSHOT_NON_HEAP_REJECT:
		parent_stats.snapshot_non_heap_reject += delta;
		break;
	case STATS_FIELD_RING_EVICTION_CORRUPT:
		parent_stats.ring_eviction_corrupt += delta;
		break;
	case STATS_FIELD_DEFERRED_FREE_CORRUPT_PTR:
		parent_stats.deferred_free_corrupt_ptr += delta;
		break;
	case STATS_FIELD_NR:
	default:
		/* Out-of-range field_id: silent drop.  A scribbled slot can
		 * carry any value; the surrounding ring overflow counter
		 * already conveys "we lost samples". */
		break;
	}
}

unsigned int stats_ring_drain(struct stats_ring *ring)
{
	uint32_t overflow = 0;
	uint32_t processed;

	if (ring == NULL)
		return 0;

	processed = spsc_ring_drain(&ring->base, ring->slots, STATS_RING_SIZE,
				    sizeof(ring->slots[0]),
				    apply_slot, NULL, &overflow);
	parent_stats.ring_overflow_total += overflow;
	return processed;
}

/*
 * Republish the mirror page from parent_stats.  Caller must have already
 * thawed the global-obj freeze (so the parent can write through to the
 * mprotected page) and will refreeze afterwards.
 *
 * Mirror integrity is verified separately by shm_is_corrupt(): between
 * this publish and the next iteration's read-back, nothing should write
 * to the mirror, so a mismatch there flags a scribble.
 */
static void stats_publish_locked(void)
{
	if (shm_published == NULL)
		return;

	shm_published->fleet_op_count = parent_stats.op_count;
}

void stats_ring_drain_all(void)
{
	unsigned int i;

	if (children == NULL)
		return;

	for_each_child(i) {
		struct childdata *child;
		struct stats_ring *ring;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;

		ring = __atomic_load_n(&child->stats_ring, __ATOMIC_ACQUIRE);
		if (ring == NULL)
			continue;

		(void) stats_ring_drain(ring);
	}

	stats_publish_locked();
}

void stats_published_init(void)
{
	shm_published = alloc_shared(sizeof(struct stats_published));
	memset(shm_published, 0, sizeof(*shm_published));
}
