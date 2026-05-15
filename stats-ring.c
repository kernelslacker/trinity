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
 * termination check.  Mirror is alloc_shared_global() so it is mprotected
 * PROT_READ after init; the drain thaws + publishes + refreezes inside
 * the same bracket that fd_event_drain_all() already uses.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "child.h"
#include "pids.h"
#include "shm.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

struct stats_aggregate parent_stats;
struct stats_published *shm_published;

void stats_ring_init(struct stats_ring *ring)
{
	memset(ring, 0, sizeof(*ring));
	atomic_store_explicit(&ring->head, 0, memory_order_relaxed);
	atomic_store_explicit(&ring->tail, 0, memory_order_relaxed);
	atomic_store_explicit(&ring->overflow, 0, memory_order_relaxed);
}

bool stats_ring_enqueue(struct stats_ring *ring, enum stats_field field,
			uint16_t aux, uint32_t delta)
{
	uint32_t head, tail, next;

	if (ring == NULL)
		return false;

	head = atomic_load_explicit(&ring->head, memory_order_relaxed);
	head &= (STATS_RING_SIZE - 1);
	tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
	tail &= (STATS_RING_SIZE - 1);

	next = (head + 1) & (STATS_RING_SIZE - 1);
	if (next == tail) {
		atomic_fetch_add_explicit(&ring->overflow, 1,
					  memory_order_relaxed);
		return false;
	}

	ring->slots[head].field_id = (uint16_t)field;
	ring->slots[head].aux = aux;
	ring->slots[head].delta = delta;
	ring->slots[head]._reserved = 0;

	atomic_store_explicit(&ring->head, next, memory_order_release);
	return true;
}

/*
 * Apply a single ring slot to parent_stats.  Validates the field_id /
 * aux combination before touching any array index -- children produce
 * hostile fuzzed workload and a wild value-result syscall buffer that
 * scribbled a slot can leave any field at any value.
 */
static void apply_slot(const struct stats_ring_slot *s)
{
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
	uint32_t head, tail, overflow;
	unsigned int processed = 0;

	if (ring == NULL)
		return 0;

	overflow = atomic_load_explicit(&ring->overflow, memory_order_relaxed);
	if (overflow != 0)
		overflow = atomic_exchange_explicit(&ring->overflow, 0,
						    memory_order_relaxed);
	if (overflow > 0)
		parent_stats.ring_overflow_total += overflow;

	tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
	tail &= (STATS_RING_SIZE - 1);
	head = atomic_load_explicit(&ring->head, memory_order_acquire);
	head &= (STATS_RING_SIZE - 1);

	while (tail != head) {
		apply_slot(&ring->slots[tail]);
		tail = (tail + 1) & (STATS_RING_SIZE - 1);
		processed++;
	}

	atomic_store_explicit(&ring->tail, tail, memory_order_release);
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
	bool was_protected;

	if (children == NULL)
		return;

	was_protected = globals_are_protected();
	if (was_protected)
		thaw_global_objects();

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

	if (was_protected)
		freeze_global_objects();
}

void stats_published_init(void)
{
	shm_published = alloc_shared_global(sizeof(struct stats_published));
	memset(shm_published, 0, sizeof(*shm_published));
}
