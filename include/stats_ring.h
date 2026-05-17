#pragma once

#include <stdbool.h>
#include <stdint.h>

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
	STATS_FIELD_OP_COUNT = 0,
	STATS_FIELD_SUCCESSES,
	STATS_FIELD_FAILURES,
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
	STATS_FIELD_SYSCALL_CATEGORY_COUNT,		/* aux = enum syscall_category */
	STATS_FIELD_POST_HANDLER_CORRUPT_PTR,
	STATS_FIELD_DEFERRED_FREE_REJECT,
	STATS_FIELD_SNAPSHOT_NON_HEAP_REJECT,
	STATS_FIELD_RING_EVICTION_CORRUPT,
	STATS_FIELD_DEFERRED_FREE_CORRUPT_PTR,
	STATS_FIELD_NR,
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
	/* Producer (child) writes head and overflow. */
	_Atomic uint32_t head;
	_Atomic uint32_t overflow;

	/* Padding to put producer and consumer fields on separate cache lines. */
	char __pad[56];

	/* Consumer (parent) writes tail. */
	_Atomic uint32_t tail;

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
};

extern struct stats_aggregate parent_stats;

/*
 * Mirror page: parent-write / child-read.  Carries the coarse fleet
 * op_count that random-syscall.c's rotation clock and child.c's
 * syscalls_todo termination need to see.  The page is alloc_shared_global,
 * so it is mprotected PROT_READ after init; the parent thaws + writes +
 * refreezes on each drain via the existing global-objects freeze bracket.
 *
 * A child wild-write into this page SEGVs the offending child at the
 * source (PROT_READ), strictly stronger than the silent in-place
 * scribble the original shm->stats.op_count permitted.
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
