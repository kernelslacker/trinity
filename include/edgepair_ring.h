#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "edgepair.h"	/* EDGEPAIR_TABLE_SIZE, struct edgepair_entry */
#include "spsc-ring.h"
#include "syscall.h"	/* MAX_NR_SYSCALL */

/*
 * Per-child SPSC ring carrying edgepair observation events from the child
 * (sole producer) to the parent (sole consumer).  Replaces direct child
 * writes to the previously-in-shm edgepair_shm->table[] + counters: the
 * 65536-slot (prev_nr, curr_nr) hash table and the three top-level
 * counters move into a parent-private struct edgepair_aggregate that no
 * kernel-visible shared mapping addresses, structurally removing the
 * wild-write attack surface for the ~1 MiB region that has been quietly
 * trusting the kernel not to scribble it.
 *
 * Same shape and topology as struct stats_ring (stats-ring.c) and struct
 * healer_ring (healer-ring.c) -- the proven SPSC pattern already
 * validated against hostile fuzzed workload.  Single fixed-size slot
 * carries (prev_nr, curr_nr, new_edges); the parent applies events
 * serially under single-writer discipline so the CAS-claim machinery
 * find_or_insert needed today collapses to a plain hash probe + store.
 *
 * Overflow policy: drop the slot silently, bump a per-ring overflow
 * counter the parent surfaces in the aggregate.  A dropped edgepair
 * event is stat noise -- the (prev, curr) pair just doesn't get its
 * bump this iteration; at worst the cold-pair detector takes longer to
 * age out a productive pair.  Blocking a child on an observer enqueue
 * is not the right tradeoff for a syscall-prior bias.
 */

#define EDGEPAIR_RING_SIZE 1024		/* power of 2; 16 KiB at 16 B/slot */

struct edgepair_event_slot {
	uint16_t prev_nr;	/* MAX_NR_SYSCALL fits in uint16 today */
	uint16_t curr_nr;
	uint8_t  new_edges;	/* 0/1 -- kcov_collect's bool return */
	uint8_t  _pad[3];
	uint64_t _reserved;	/* pad to 16 B; matches stats slot shape */
};				/* 16 bytes total */

struct edgepair_ring {
	struct spsc_ring base;
	struct edgepair_event_slot slots[EDGEPAIR_RING_SIZE];
};

/*
 * Parent-private aggregate.  Lives in the parent's MAP_PRIVATE heap
 * (post-fork .bss); no kernel-visible shared mapping addresses it, so
 * a wild kernel write through any child syscall arg cannot scribble
 * the table or the counters.  Children inherit a COW copy at fork time
 * but the convention is that children only ever enqueue into their
 * edgepair_ring; the aggregate is read-only from child context and
 * accessed via the published mirror page (for the one child-read site
 * that exists, edgepair_is_cold) or through parent-canonical lookups
 * for the parent-side consumers (edgepair_get_stats, dump, stats).
 *
 * Same slot layout as the shm table it shadows -- struct edgepair_entry
 * carries the CAS-key union which is harmless as plain memory parent-
 * side; the union is removed in the final commit of this stage once
 * the in-shm path is gone.
 */
struct edgepair_aggregate {
	/* Canonical (prev_nr, curr_nr) hash table.  Same shape as the shm
	 * version, same EDGEPAIR_EMPTY sentinel for empty slots, same
	 * linear-probe + EDGEPAIR_MAX_PROBE chain length.  Parent is the
	 * sole writer; no per-slot atomic discipline needed. */
	struct edgepair_entry table[EDGEPAIR_TABLE_SIZE];

	/* Top-level counters lifted out of struct edgepair_shared.  Same
	 * semantics as the in-shm versions they shadow; counted on the
	 * apply path under single-writer discipline. */
	unsigned long total_pair_calls;
	unsigned long pairs_tracked;
	unsigned long pairs_dropped;

	/* Visibility / health counters surfaced via the dump. */
	unsigned long ring_overflow_total;
	unsigned long published_corrupt;	/* mirror page disagreed with canonical */
};

extern struct edgepair_aggregate parent_edgepair;

/*
 * Mirror page: parent-write / child-read.  Carries the published view
 * of the canonical table so the child-side cold-pair check
 * (edgepair_is_cold at random-syscall.c) can read its three fields
 * without a ring round-trip.
 *
 * Carries the trimmed slot view (prev_nr, curr_nr, new_edge_count,
 * last_new_at) plus the total_pair_calls "now" anchor in a header
 * word.  total_count is parent-only-consumed and stays out of the
 * mirror; pairs_tracked / pairs_dropped are parent-read-only for
 * stats display and served by parent-canonical lookup.
 *
 * Full publish per drain (~1.5 MiB memcpy on the ms-cadence drain).
 * No dirty-row tracking -- the publish path is a straight memcpy and
 * the apply path doesn't naturally produce per-row dirty signal
 * without extra accounting; staleness is bounded by the drain cadence
 * which is operationally indistinguishable from fresh for the
 * EDGEPAIR_COLD_THRESHOLD scale (100000 pair-calls).
 */
struct edgepair_published_slot {
	unsigned int  prev_nr;		/* matches edgepair_entry.prev_nr */
	unsigned int  curr_nr;
	unsigned long new_edge_count;
	unsigned long last_new_at;
};					/* 24 bytes per slot */

struct edgepair_published {
	unsigned long total_pair_calls;	/* the "now" anchor for cold staleness */
	unsigned long _pad[2];		/* align slots[] to 24 B */
	struct edgepair_published_slot slots[EDGEPAIR_TABLE_SIZE];
};

extern struct edgepair_published *edgepair_published;

void edgepair_ring_init(struct edgepair_ring *ring);

/*
 * Per-child edgepair reset contract called from clean_childdata() when
 * a child slot is reused.  Reinitialises the per-child observation
 * ring so a fresh occupant cannot inherit pending ring state from the
 * prior occupant of the slot.
 */
struct childdata;
void edgepair_child_reset(struct childdata *child);

/*
 * Enqueue an edgepair observation event from child context.  Lock-free,
 * returns false if the ring is full (slot dropped, overflow counter
 * bumped).
 */
bool edgepair_ring_enqueue(struct edgepair_ring *ring,
			   unsigned int prev_nr, unsigned int curr_nr,
			   bool new_edges);

/*
 * Drain all pending slots from one child's ring, applying events to
 * parent_edgepair.  Single-consumer: only the parent writes tail.
 * Returns the number of slots processed.
 */
unsigned int edgepair_ring_drain(struct edgepair_ring *ring);

/*
 * Drain every child's ring and republish the mirror page.  Called from
 * the parent main loop alongside stats_ring_drain_all() and
 * healer_ring_drain_all().
 */
void edgepair_ring_drain_all(void);

/*
 * Allocate the mirror page.  Called from init_shm().
 */
void edgepair_published_init(void);
