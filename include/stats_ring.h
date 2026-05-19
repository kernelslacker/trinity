#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "spsc-ring.h"
#include "stats.h"	/* NR_SYSCAT */
#include "syscall.h"	/* MAX_NR_SYSCALL */

/*
 * Per-child SPSC ring carrying stats deltas from the child (sole producer)
 * to the parent (sole consumer).  Replaces direct child writes to
 * shm->stats for the hot per-syscall counters: those fields move into
 * a parent-private aggregate (struct stats_aggregate) that no kernel-
 * visible shared mapping points at, structurally removing the wild-
 * write attack surface for those fields.
 *
 * Same shape and topology as struct fd_event_ring (fd-event.c) which is
 * already proven in this codebase under hostile fuzzed workload for the
 * write-only-by-child / read-only-by-parent contract.
 *
 * Overflow policy: drop the slot silently, bump a per-ring overflow
 * counter the parent surfaces in the aggregate.  Stats accuracy is
 * best-effort; blocking a child on a stats enqueue is not.
 */

#define STATS_RING_SIZE 1024	/* power of 2; 16 KiB at 16 B/slot */

/*
 * One enum value per stats counter that has moved from shm into the
 * parent aggregate.  The drain switches on field_id; aux carries the
 * sub-index for fields that are arrays (per-syscall reject buckets,
 * the syscall-category histogram), and is unused (0) for plain scalars.
 */
enum stats_field {
	STATS_FIELD_OP_COUNT = 0,	/* alt-op bumps only; dispatched syscalls
					 * fold op_count into CALL_COMPLETE */
	STATS_FIELD_FAULT_INJECTED,
	STATS_FIELD_FAULT_CONSUMED,
	STATS_FIELD_SHARED_BUFFER_REDIRECTED,
	STATS_FIELD_LIBC_HEAP_REDIRECTED,
	STATS_FIELD_LIBC_HEAP_EMBEDDED_REDIRECTED,
	STATS_FIELD_RANGE_OVERLAPS_SHARED_REJECTS,
	STATS_FIELD_GET_WRITABLE_SCRIBBLED,
	STATS_FIELD_CHILDREN_RECYCLED_ON_STORM,
	STATS_FIELD_UNSHARE_NEWNET_THROTTLED,
	STATS_FIELD_RANGE_REJECTS_PER_SYSCALL_64,	/* aux = syscall nr */
	STATS_FIELD_RANGE_REJECTS_PER_SYSCALL_32,	/* aux = syscall nr */
	STATS_FIELD_POST_HANDLER_CORRUPT_PTR,
	STATS_FIELD_DEFERRED_FREE_REJECT,
	STATS_FIELD_SNAPSHOT_NON_HEAP_REJECT,
	STATS_FIELD_RING_EVICTION_CORRUPT,
	STATS_FIELD_DEFERRED_FREE_CORRUPT_PTR,
	/*
	 * Combined "call complete" slot.  A single enqueue carries the
	 * three bumps every completed dispatched syscall used to emit
	 * separately (op_count, success/failure, syscall_category_count):
	 *   - aux        = enum syscall_category
	 *   - delta      = op_count delta (always 1 on the hot path)
	 *   - _reserved  = enum stats_result_class in low byte
	 * Drain expands one slot into three logical bumps, cutting the
	 * SPSC enqueue count per dispatched syscall from three to one.
	 */
	STATS_FIELD_CALL_COMPLETE,
	STATS_FIELD_NR,
};

/*
 * Result class encoded in stats_ring_slot._reserved low byte for
 * STATS_FIELD_CALL_COMPLETE.  INCOMPLETE covers EXTRA_FORK grandchildren
 * that were SIGKILL'd before reaching __do_syscall's AFTER block: the
 * dispatched call still earned its op_count and category bumps but
 * neither successes nor failures applies.  Any other byte value seen on
 * drain is treated as INCOMPLETE so a scribbled slot can't manufacture
 * a success/failure attribution.
 */
enum stats_result_class {
	STATS_RESULT_INCOMPLETE = 0,
	STATS_RESULT_SUCCESS = 1,
	STATS_RESULT_FAILURE = 2,
};

struct stats_ring_slot {
	uint16_t field_id;	/* enum stats_field */
	uint16_t aux;		/* per-array index, or 0 for scalars */
	uint32_t delta;		/* +1 per syscall on the common paths;
				 * larger values reserved for future batched
				 * paths */
	uint64_t _reserved;	/* pad to 16 B; future use (e.g. caller PC) */
};

struct stats_ring {
	struct spsc_ring base;
	struct stats_ring_slot slots[STATS_RING_SIZE];
};

/*
 * Parent-private aggregate.  Lives in the parent's MAP_PRIVATE heap
 * (post-fork .bss); no kernel-visible shared mapping addresses it, so
 * a wild kernel write through any child syscall arg cannot scribble
 * these fields.  Children inherit a COW copy at fork time and can
 * locally mutate it without affecting the parent's view -- but the
 * convention is that children only ever write to their stats_ring;
 * parent_stats is read-only from child context.
 *
 * Field set mirrors struct stats_s Group A: see include/stats.h
 * lines 119-219.  The ring drain is the only writer (beyond the
 * parent's own reset/init paths).
 */
struct stats_aggregate {
	unsigned long op_count;
	unsigned long previous_op_count;
	unsigned long successes;
	unsigned long failures;
	unsigned long fault_injected;
	unsigned long fault_consumed;
	unsigned long shared_buffer_redirected;
	unsigned long libc_heap_redirected;
	unsigned long libc_heap_embedded_redirected;
	unsigned long range_overlaps_shared_rejects;
	unsigned long get_writable_address_scribbled_slots_caught;
	unsigned long children_recycled_on_storm;
	unsigned long unshare_newnet_throttled;
	unsigned long range_overlaps_shared_rejects_per_syscall_64[MAX_NR_SYSCALL];
	unsigned long range_overlaps_shared_rejects_per_syscall_32[MAX_NR_SYSCALL];
	unsigned long syscall_category_count[NR_SYSCAT];

	/* Group B headline counters lifted out of struct stats_s alongside
	 * the corruption-attribution shards.  Children enqueue +1 deltas via
	 * the stats_ring; the parent drain accumulates here.  The defense-
	 * counter periodic dump reads these via the from_aggregate path. */
	unsigned long post_handler_corrupt_ptr;
	unsigned long deferred_free_reject;
	unsigned long snapshot_non_heap_reject;
	unsigned long ring_eviction_corrupt;
	unsigned long deferred_free_corrupt_ptr;

	/* Visibility / health counters surfaced via dump_stats. */
	unsigned long ring_overflow_total;	/* sum of dropped enqueues across all rings */
	unsigned long shm_published_corrupt;	/* mirror page disagreed with parent_stats */

	/* check_lock() observed LOCK_RESERVED_DIRTY(state) on the periodic
	 * sanity walk and called force_bust_lock() to recover.  Bumped from
	 * main context only (sole walker), so plain ++ is safe.  Lives in
	 * parent_stats rather than shm->stats so a wild kernel write through
	 * a fuzzed syscall arg -- the very class of event this counter
	 * tracks -- cannot scribble the diagnostic that detects it. */
	unsigned long lock_word_scribbled;
};

extern struct stats_aggregate parent_stats;

/*
 * Mirror page: parent-write / child-read.  Carries the coarse fleet
 * op_count that random-syscall.c's rotation clock and child.c's
 * syscalls_todo termination need to see.  The parent republishes on
 * each drain.
 */
struct stats_published {
	unsigned long fleet_op_count;
};

extern struct stats_published *shm_published;

void stats_ring_init(struct stats_ring *ring);

/*
 * Enqueue a stats delta from child context.  Lock-free, returns false
 * if the ring is full (slot dropped, overflow counter bumped).
 */
bool stats_ring_enqueue(struct stats_ring *ring, enum stats_field field,
			uint16_t aux, uint32_t delta);

/*
 * Enqueue one combined "call complete" slot covering op_count,
 * success/failure, and syscall_category_count[] in a single SPSC
 * operation.  Use from the dispatch path after handle_syscall_ret()
 * has settled rec->retval and rec->state.
 */
bool stats_ring_enqueue_call_complete(struct stats_ring *ring,
				      uint16_t category,
				      enum stats_result_class result);

/*
 * Drain all pending slots from one child's ring, applying deltas to
 * parent_stats.  Single-consumer: only the parent writes tail.
 * Returns the number of slots processed.
 */
unsigned int stats_ring_drain(struct stats_ring *ring);

/*
 * Drain every child's ring and republish the mirror page.  Called from
 * the parent main loop alongside fd_event_drain_all().
 */
void stats_ring_drain_all(void);

/*
 * Allocate the shm_published mirror page.  Called from init_shm().
 */
void stats_published_init(void);

/*
 * Per-child mprotect freeze of the shm_published mirror page to
 * PROT_READ.  Called from init_child() so children see a read-only
 * view of the parent-write / child-read mirror.  Mirrors the
 * healer_published_freeze() / edgepair_published_freeze() helpers.
 */
void stats_published_freeze(void);
