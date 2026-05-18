#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "healer.h"	/* HEALER_RELATION_SLOTS, struct healer_relation */
#include "syscall.h"	/* MAX_NR_SYSCALL */

/*
 * Per-child SPSC ring carrying HEALER observation events from the child
 * (sole producer) to the parent (sole consumer).  Replaces direct child
 * writes to the previously-in-shm healer_relations[] / pair_table[][] for
 * the hot new-edge observer-hook path: both tables move into a parent-
 * private canonical (struct healer_aggregate) that no kernel-visible
 * shared mapping points at, structurally removing the wild-write attack
 * surface for the largest single region in shm today (~5.13 MiB across
 * the two tables combined).
 *
 * Same shape and topology as struct stats_ring (stats-ring.c) -- itself
 * modeled on the proven struct fd_event_ring -- which is already
 * validated in this codebase for the write-only-by-child / read-only-by-
 * parent contract under hostile fuzzed workload.
 *
 * Two event kinds packed into a single fixed slot type so the drain
 * stays branchless on slot fetch and only branches on `kind` for the
 * apply step.  Triple events carry (pred_a, pred_b, succ) and feed the
 * relation table; pair events carry (pred, succ) and feed the dense
 * pair-relation matrix.  Both kinds fire together from the same
 * observer-hook call site on every new-edge fire (random-syscall.c),
 * so two enqueues per fire is the expected steady-state cost.
 *
 * Overflow policy: drop the slot silently, bump a per-ring overflow
 * counter the parent surfaces in the aggregate.  HEALER's per-sample
 * value is higher in the cold-start regime than the post-saturation
 * steady state (where the table is saturated and dropped slots are
 * overwhelmingly likely to be re-observed within seconds); drop is the
 * right default and blocking a child on an observer enqueue is not.
 */

#define HEALER_RING_SIZE 1024	/* power of 2; 8 KiB at 8 B/slot */

enum healer_event_kind {
	HEALER_EVT_TRIPLE = 1,	/* (pred_a, pred_b, succ) into relation table */
	HEALER_EVT_PAIR   = 2,	/* (pred, succ) into pair-relation matrix */
};

struct healer_event_slot {
	uint16_t kind;		/* enum healer_event_kind; 0 marks "scribbled" */
	uint16_t pred_a;	/* HEALER_EVT_TRIPLE only; 0 for PAIR */
	uint16_t pred_b;	/* triple's pred_b OR pair's pred */
	uint16_t succ;		/* in both kinds */
};				/* 8 bytes total */

struct healer_ring {
	/* Producer (child) writes head and overflow. */
	uint32_t head;
	uint32_t overflow;

	/* Padding to put producer and consumer fields on separate cache lines. */
	char __pad[56];

	/* Consumer (parent) writes tail. */
	uint32_t tail;

	struct healer_event_slot slots[HEALER_RING_SIZE];
};

/*
 * One pair-table cell.  Splits the predecessor->successor relation into
 * three named components instead of cramming all of them into a single
 * integer weight:
 *
 *   static_prior        - install weight from the producer/consumer
 *                         classifier (healer_load_static_seed).  Never
 *                         decays; carries the prior independently of any
 *                         runtime evidence.  uint8_t is comfortable for
 *                         HEALER_STATIC_SEED_WEIGHT (currently 3) and any
 *                         plausible re-tuning.
 *   dynamic_hits        - count of runtime observations (apply_pair
 *                         increments under saturation cap).  This is the
 *                         only field the pair-row decay halves, so a
 *                         long quiet phase relaxes the dynamic signal
 *                         without erasing the static prior beneath it.
 *   last_observed_epoch - decay_epoch stamped at the most recent
 *                         apply_pair bump.  Placeholder for the pair-
 *                         table prune walk (separate follow-up); stamped
 *                         here so the prune logic can land without
 *                         backfilling history.
 *
 * Layout is naturally aligned: uint32_t at offset 0, uint16_t at 4,
 * two uint8_t at 6-7, total 8 bytes.  The mirror page is a flat array
 * of these cells so picker reads see static_prior and dynamic_hits in
 * a single 8-byte cell load.  Reads are not atomic against the parent's
 * publish step; the existing comment on healer_pair_published already
 * documents that picker tolerates bounded per-drain staleness, and a
 * partially-published cell only mixes old and new field values from
 * the same cell -- relative magnitudes stay sane.
 */
struct healer_pair_cell {
	uint32_t dynamic_hits;
	uint16_t last_observed_epoch;
	uint8_t static_prior;
	uint8_t _pad;
};

/*
 * Parent-private aggregate.  Lives in the parent's MAP_PRIVATE heap
 * (post-fork .bss); no kernel-visible shared mapping addresses it, so
 * a wild kernel write through any child syscall arg cannot scribble
 * either table.  Children inherit a COW copy at fork time but the
 * convention is that children only ever enqueue into their healer_ring;
 * healer_aggregate is read-only from child context and accessed via
 * the published mirror pages.
 *
 * Holds the relation + pair tables (formerly in shm) at their
 * original dimensions: same slot layout, different storage class.
 * The ring drain is the only writer beyond
 * the parent's own seed/load paths (healer_load_static_seed,
 * healer_load_file).
 */
struct healer_aggregate {
	/* Canonical triple table: same shape as the shm version, indexed
	 * by FNV-1a(sorted (pred_a, pred_b)) masked to HEALER_RELATION_SLOTS.
	 * Parent is the sole writer; no per-slot atomic discipline needed. */
	struct healer_relation relations[HEALER_RELATION_SLOTS];

	/* Canonical pair table: dense MAX_NR_SYSCALL x MAX_NR_SYSCALL
	 * matrix indexed (pred -> succ).  Each cell carries the (static
	 * prior, dynamic hits, last observation epoch) triple separately
	 * so decay, dump and the eligibility gate can speak directly to
	 * the component they care about; see struct healer_pair_cell. */
	struct healer_pair_cell pair_table[MAX_NR_SYSCALL][MAX_NR_SYSCALL];

	/* Dirty-row tracking for the publish step.  Set when the parent's
	 * drain mutates a slot or row; cleared after the publish copies
	 * the row into the mirror page.  Without this, the worst-case
	 * publish would memcpy ~5 MiB per drain (a few GB/s of memory
	 * bandwidth on a hot fleet box) -- with it, steady-state publish
	 * cost is <10 KiB per drain. */
	uint8_t relations_dirty[HEALER_RELATION_SLOTS];
	uint8_t pair_dirty[MAX_NR_SYSCALL];

	/* Per-slot prune clock.  Each entry holds the decay_epoch value
	 * the slot was last refreshed at (apply_triple stamps it on every
	 * claim/bump/evict).  The decay walk uses (decay_epoch -
	 * last_refreshed) to decide when a slot has aged out of usefulness
	 * and can be reclaimed -- see HEALER_PRUNE_EPOCHS in healer-ring.c.
	 * Lives parallel to relations[] rather than inside struct
	 * healer_relation so the on-disk persistence layout (which bulk
	 * memcpys the relations array) stays unchanged.  uint16_t matches
	 * decay_epoch and is wrap-safe for the small comparison distance
	 * the prune check needs. */
	uint16_t relations_last_refreshed[HEALER_RELATION_SLOTS];

	/* Eviction / probe-limit / observation counters lifted out of
	 * shm->stats.healer_*.  Parent-private, written by apply, read by
	 * dump.  Same semantics as the in-shm counters they shadow. */
	unsigned long relations_observed;
	unsigned long table_full;
	unsigned long evictions;
	unsigned long pred_appearance[MAX_NR_SYSCALL];

	/* Decay election state.  Becomes single-writer parent state once
	 * apply runs in parent context, so no CAS election is needed --
	 * see healer_apply_maybe_decay() in healer-ring.c.  decay_epoch
	 * advances by one on every decay run and is the reference clock
	 * used by the per-slot prune machinery (see relations_last_refreshed
	 * below) to decide when an untouched slot has aged out.  uint16_t
	 * because the prune comparison only needs wrap-distance accuracy,
	 * and even at the fastest decay cadence (~5000 observations) the
	 * counter wraps no sooner than years of continuous fuzzing -- far
	 * past any plausible run lifetime. */
	unsigned long obs_at_last_decay;
	unsigned long time_at_last_decay;
	unsigned long weight_decays_run;
	uint16_t decay_epoch;

	/* Snapshot election state, same single-writer collapse. */
	unsigned long obs_at_last_snapshot;
	unsigned long last_snapshot_time;
	unsigned long snapshot_overruns;	/* never tripped post-retrofit;
						 * kept for dump-format parity */

	/* Static-seed install counter; mirror of shm->stats.healer_pair_seeded. */
	unsigned long pair_seeded;

	/* Visibility / health counters surfaced via the dump. */
	unsigned long ring_overflow_total;
	unsigned long published_corrupt;	/* mirror page disagreed with canonical */
};

extern struct healer_aggregate parent_healer;

/*
 * Mirror pages: parent-write / child-read.  Carry the published view of
 * the canonical tables so the child-side picker (set_syscall_nr_healer)
 * can read weights without a ring round-trip.  The parent writes the
 * dirty rows once per drain.
 *
 * The picker reads from these pages directly -- same probe + row-scan
 * shape as the in-shm version, different base pointer.  Bounded
 * staleness (per-drain, ~ms) is operationally indistinguishable from
 * fresh for a syscall-prior bias that evolves on second-to-hour
 * timescales.
 */
extern struct healer_relation *healer_relations_published;
extern struct healer_pair_cell (*healer_pair_published)[MAX_NR_SYSCALL];

void healer_ring_init(struct healer_ring *ring);

/*
 * Per-child HEALER reset contract called from clean_childdata() when a
 * child slot is reused.  Clears the per-child seq buffer (slots stamped
 * with EDGEPAIR_NO_PREV, count zeroed) and reinitialises the per-child
 * observation ring so a fresh occupant cannot inherit predecessor
 * context or pending ring state from the prior occupant of the slot.
 */
struct childdata;
void healer_child_reset(struct childdata *child);

/*
 * Enqueue a HEALER observation event from child context.  Lock-free,
 * returns false if the ring is full (slot dropped, overflow counter
 * bumped).  Two helpers for the two event kinds so call sites don't
 * have to build the slot struct by hand.
 */
bool healer_ring_enqueue_triple(struct healer_ring *ring,
				unsigned int pred_a, unsigned int pred_b,
				unsigned int succ);
bool healer_ring_enqueue_pair(struct healer_ring *ring,
			      unsigned int pred, unsigned int succ);

/*
 * Drain all pending slots from one child's ring, applying events to
 * parent_healer.  Single-consumer: only the parent writes tail.
 * Returns the number of slots processed.
 */
unsigned int healer_ring_drain(struct healer_ring *ring);

/*
 * Drain every child's ring, run decay if its trigger fires, and
 * republish the dirty rows of both mirror pages.  Called from the
 * parent main loop alongside stats_ring_drain_all().
 */
void healer_ring_drain_all(void);

/*
 * Allocate the two mirror pages.  Called from init_shm().
 */
void healer_published_init(void);

/*
 * Mprotect the two mirror pages PROT_READ in the calling process.
 * Called from the per-child post-fork init hook so children see the
 * mirrors read-only -- a wild kernel store through a fuzzed syscall
 * arg pointer that lands in the mirror page now SIGSEGVs in the
 * offending child instead of silently corrupting the picker's view.
 * The parent's mapping stays RW (mprotect is per-process) so the
 * drain-side publish keeps working unchanged.  Best-effort: logs and
 * continues on failure rather than crashing the child.
 */
void healer_published_freeze(void);

/*
 * Set a pair cell's static prior on the apply path that runs from the
 * parent's own pre-fork seed installer.  The seed installer writes
 * parent_healer directly (no ring) and needs the row's dirty bit set
 * so the first publish propagates the seed values to the mirror.
 * Idempotent: only installs when the cell's static_prior is still zero,
 * so a second walk over an already-seeded cell is a silent no-op.  Does
 * not touch dynamic_hits -- the seed install is a metadata-only fact
 * about the (pred, succ) pair and carries no runtime observation.
 */
void healer_aggregate_pair_set(unsigned int pred, unsigned int succ,
			       unsigned int weight);
