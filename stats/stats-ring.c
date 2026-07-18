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

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>

#include "arch.h"		/* page_size, PAGE_MASK */
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

bool stats_ring_enqueue_call_complete(struct stats_ring *ring,
				      uint16_t category,
				      enum stats_result_class result)
{
	struct stats_ring_slot slot = {
		.field_id = (uint16_t)STATS_FIELD_CALL_COMPLETE,
		.aux = category,
		.delta = 1,
		._reserved = (uint64_t)(uint8_t)result,
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
	case STATS_FIELD_ASB_RELOCATE_READABLE_SKIP:
		parent_stats.asb_relocate_readable_skip += delta;
		break;
	case STATS_FIELD_ASB_RELOCATE_COPY_FAULT:
		parent_stats.asb_relocate_copy_fault += delta;
		break;
	case STATS_FIELD_HEAP_POINTER_OUTSIDE_CACHE:
		parent_stats.heap_pointer_outside_cache += delta;
		break;
	case STATS_FIELD_HEAP_BRK_STALE_WINDOW_HIT:
		parent_stats.heap_brk_stale_window_hit += delta;
		break;
	case STATS_FIELD_RANGE_OVERLAPS_SHARED_REJECTS:
		parent_stats.range_overlaps_shared_rejects += delta;
		break;
	case STATS_FIELD_CHILDREN_RECYCLED_ON_STORM:
		parent_stats.children_recycled_on_storm += delta;
		break;
	case STATS_FIELD_WATCHDOG_FD_EVICT:
		parent_stats.watchdog_fd_evict += delta;
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
	case STATS_FIELD_POST_HANDLER_CORRUPT_PTR:
		parent_stats.post_handler_corrupt_ptr += delta;
		break;
	case STATS_FIELD_VALIDATOR_REJECTED:
		parent_stats.validator_rejected += delta;
		break;
	case STATS_FIELD_ARG_CONSTRAINT_REPAIRED:
		parent_stats.arg_constraint_repaired += delta;
		break;
	case STATS_FIELD_ARG_CONSTRAINT_KEPT_INCOHERENT:
		parent_stats.arg_constraint_kept_incoherent += delta;
		break;
	case STATS_FIELD_DEFERRED_FREE_REJECT:
		parent_stats.deferred_free_reject += delta;
		break;
	case STATS_FIELD_DEFERRED_FREE_REJECT_PATHNAME:
		parent_stats.deferred_free_reject_pathname += delta;
		break;
	case STATS_FIELD_DEFERRED_FREE_REJECT_IOVEC:
		parent_stats.deferred_free_reject_iovec += delta;
		break;
	case STATS_FIELD_DEFERRED_FREE_REJECT_SOCKADDR:
		parent_stats.deferred_free_reject_sockaddr += delta;
		break;
	case STATS_FIELD_DEFERRED_FREE_REJECT_OTHER:
		parent_stats.deferred_free_reject_other += delta;
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
	case STATS_FIELD_ARG_SHADOW_STOMP:
		parent_stats.arg_shadow_stomp += delta;
		break;
	case STATS_FIELD_TOTAL_CALLS:
		parent_stats.total_calls += delta;
		break;
	case STATS_FIELD_REMOTE_CALLS:
		parent_stats.remote_calls += delta;
		break;
	case STATS_FIELD_TOTAL_PCS:
		parent_stats.total_pcs += delta;
		break;
	case STATS_FIELD_WARM_KNOWN_HITS:
		parent_stats.total_warm_known_hits += delta;
		break;
	case STATS_FIELD_CMP_HINTS_TRY_GET_ATTEMPTS:
		parent_stats.cmp_hints_try_get_attempts += delta;
		break;
	case STATS_FIELD_CMP_HINTS_TRY_GET_RETURNED:
		parent_stats.cmp_hints_try_get_returned += delta;
		break;
	case STATS_FIELD_PER_SYSCALL_CMP_ATTEMPTS:
		if (aux < MAX_NR_SYSCALL)
			parent_stats.per_syscall_cmp_attempts[aux] += delta;
		break;
	case STATS_FIELD_PER_SYSCALL_CMP_RETURNED:
		if (aux < MAX_NR_SYSCALL)
			parent_stats.per_syscall_cmp_returned[aux] += delta;
		break;
	case STATS_FIELD_PER_SYSCALL_CMP_HYP_LIVE_INJECTED:
		if (aux < MAX_NR_SYSCALL)
			parent_stats.per_syscall_cmp_hyp_live_injected[aux] += delta;
		break;
	case STATS_FIELD_MM_GATE_POST_SLIP:
		parent_stats.mm_gate_post_slip += delta;
		break;
	case STATS_FIELD_CALL_COMPLETE: {
		/* One slot, three logical bumps.  op_count is unconditional
		 * (the SPSC slot wouldn't have made it past spsc_ring_drain
		 * without head/tail ordering, so its arrival IS the proof
		 * that a child dispatched a syscall).  category is gated on
		 * aux < NR_SYSCAT; a scribbled aux loses just the category
		 * bump for this slot.  successes/failures is gated on a
		 * known result_class; any other byte value in _reserved is
		 * treated as INCOMPLETE so a scribbled slot cannot fabricate
		 * a success/failure attribution. */
		uint8_t result = (uint8_t)s->_reserved;

		parent_stats.op_count += delta;
		if (aux < NR_SYSCAT)
			parent_stats.syscall_category_count[aux] += delta;
		if (result == STATS_RESULT_SUCCESS)
			parent_stats.successes += delta;
		else if (result == STATS_RESULT_FAILURE)
			parent_stats.failures += delta;
		break;
	}
	case STATS_FIELD_NR:
	default:
		/* Out-of-range field_id: silent drop.  A scribbled slot can
		 * carry any value; the surrounding ring overflow counter
		 * already conveys "we lost samples". */
		break;
	}
}

static unsigned int stats_ring_drain(struct stats_ring *ring)
{
	uint64_t overflow = 0;
	uint32_t processed;

	if (ring == NULL)
		return 0;

	processed = spsc_ring_drain(&ring->base, ring->slots, STATS_RING_SIZE,
				    sizeof(ring->slots[0]),
				    apply_slot, NULL, &overflow);
	parent_stats.ring_overflow_total += overflow;
	parent_stats.ring_slots_processed_total += processed;
	parent_stats.ring_drain_children_visited += 1;
	if (overflow > 0)
		parent_stats.ring_children_overflow_events += 1;
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

	__atomic_store_n(&shm_published->fleet_op_count, parent_stats.op_count,
			 __ATOMIC_RELAXED);
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

		/*
		 * Sanity-check the ring pointer before dereferencing it.
		 * A D-state zombie waking after its slot was recycled can
		 * write a wild pointer here.  fd_event_drain_all() caught
		 * 0x9c000000890000 in the wild (bit 47 set, bits 48-63
		 * clear -- non-canonical on x86-64).  Catch that pattern
		 * and any obviously low address rather than taking a
		 * SIGSEGV that would take the parent down.
		 */
		{
			uintptr_t raddr = (uintptr_t)ring;
			uintptr_t top = raddr >> 47;

			if (raddr < 0x10000 ||
			    (top != 0 && top != 0x1ffff)) {
				output(0, "stats_ring: child[%u] ring pointer %p is non-canonical, skipping\n",
				       i, ring);
				__atomic_add_fetch(&shm->stats.stats_ring_corrupted, 1,
						   __ATOMIC_RELAXED);
				continue;
			}
		}

		/*
		 * Canary check: compare the live pointer against the
		 * known-good value captured at init time.  A mismatch means
		 * the pointer field was overwritten after init (e.g. a stray
		 * write from a recycled child slot).  Use the expected
		 * pointer for the drain so fuzzing can continue, but only
		 * after it passes the same sanity check we applied to the
		 * live pointer above.
		 */
		if (ring != expected_stats_rings[i]) {
			struct stats_ring *expected = expected_stats_rings[i];
			uintptr_t eaddr = (uintptr_t)expected;
			uintptr_t etop = eaddr >> 47;

			output(0, "stats_ring: child[%u] ring pointer %p overwritten (expected %p)\n",
			       i, ring, expected);
			__atomic_add_fetch(&shm->stats.stats_ring_overwritten, 1,
					   __ATOMIC_RELAXED);

			if (eaddr < 0x10000 ||
			    (etop != 0 && etop != 0x1ffff)) {
				output(0, "stats_ring: child[%u] expected ring %p also non-canonical, skipping\n",
				       i, expected);
				continue;
			}
			ring = expected;
		}

		(void) stats_ring_drain(ring);
	}

	stats_publish_locked();
}

void stats_published_init(void)
{
	shm_published = alloc_shared(sizeof(struct stats_published));
	memset(shm_published, 0, sizeof(*shm_published));
}

/*
 * Per-child mprotect freeze of the shm_published mirror page.  The
 * mirror is parent-write / child-read: children read fleet_op_count
 * off it on the cold path (maybe_rotate_strategy()'s rotation clock
 * in random-syscall.c and the syscalls_todo termination check in
 * child_process()), and the parent's stats_publish_locked() inside
 * stats_ring_drain_all() is the sole writer.  The mirror-integrity
 * sample in shm_is_corrupt() (main/loop.c) already documents the
 * PROT_READ contract -- "republish-time we wrote ... and then
 * mprotected the page PROT_READ" -- but the matching mprotect()
 * call was missing, leaving the contract as comment only.  A wild
 * kernel store through a fuzzed syscall arg pointer could scribble
 * fleet_op_count between publishes, perturbing the rotation clock
 * and syscalls_todo progress; the integrity check would only flag
 * the damage post-hoc.
 *
 * Called from the per-child post-fork init hook so the freeze
 * applies in child address space.  mprotect is per-process, so the
 * parent's mapping stays PROT_READ|PROT_WRITE and the drain's
 * publish keeps writing through; only children see the read-only
 * view.
 *
 * Best-effort on failure: log via the canonical helper and continue.
 * mprotect can ENOMEM if the kernel runs out of VMA slots splitting
 * the mapping that backs the mirror (same failure mode as the
 * freeze_sibling_childdata sweep) and turning a transient kernel
 * limit into a fleet-wide crash would be
 * worse than leaving the mirror RW for the lifetime of the affected
 * child.
 */
void stats_published_freeze(void)
{
	size_t bytes;

	if (shm_published == NULL)
		return;

	bytes = sizeof(struct stats_published);
	bytes = (bytes + page_size - 1) & PAGE_MASK;
	if (mprotect(shm_published, bytes, PROT_READ) != 0)
		log_mprotect_failure(shm_published, bytes, PROT_READ,
				     __builtin_return_address(0), errno);
}
