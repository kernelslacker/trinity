/*
 * Per-child HEALER observation ring buffer + parent-side canonical
 * aggregate + child-RO mirror pages.
 *
 * Children produce unified observation slots (one per new-edge syscall:
 * pred_prev, pred_last, succ, plus the edge-bucket count and reserved
 * flags / result-class fields) into their own ring (write-only-by-
 * owner); the parent drains every ring once per main_loop iteration and
 * applies BOTH the pair-table bump (pred_last -> succ) AND the triple-
 * table bump (sort(pred_prev, pred_last) -> succ) from the same slot,
 * writing into a parent-private struct healer_aggregate that lives in
 * MAP_PRIVATE memory invisible to the kernel.  The kernel can no longer
 * scribble either table via a wild syscall arg pointer because the
 * authoritative copy is not at any kernel-visible address.
 *
 * Two mirror pages (healer_relations_published, healer_pair_published)
 * are republished from the canonical at every drain so the child-side
 * picker (set_syscall_nr_healer) can read weights without a ring round-
 * trip.  Dirty-row tracking keeps the publish cost at ~KiB/drain steady
 * state instead of the worst-case 5 MiB memcpy a naive full-table
 * publish would cost.
 *
 * Single-writer apply collapses the CAS machinery the in-shm path
 * needed: triple-table promoted-entry insertion is a straight scan +
 * eviction by lowest-weight, no per-slot CAS loop, no restart_budget.
 * Pair-table bumps are plain stores with saturation clamp.  Decay
 * becomes a straight walk on its trigger; no CAS election.
 */

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "arch.h"		/* page_size */
#include "child.h"
#include "edgepair.h"		/* EDGEPAIR_NO_PREV */
#include "healer.h"
#include "healer_ring.h"
#include "pids.h"
#include "shm.h"
#include "spsc-ring.h"
#include "trinity.h"
#include "utils.h"

struct healer_aggregate parent_healer;
struct healer_relation *healer_relations_published;
struct healer_pair_cell (*healer_pair_published)[MAX_NR_SYSCALL][MAX_NR_SYSCALL];

/* Mirror healer.c's per-cell saturation cap and decay cadences.  Kept
 * as local statics so this file is self-contained for the dark-launch
 * commit; once the in-shm tables are gone they remain the only
 * definitions in the tree. */
#define HEALER_PAIR_MAX_WEIGHT		(1U << 24)
#define HEALER_DECAY_OBSERVATIONS	5000UL
#define HEALER_DECAY_INTERVAL_SEC	1800UL

/*
 * Per-event weight cap.  edge_delta from kcov_collect can spike on a
 * single new-edge call that uncovers a whole subsystem's worth of
 * coverage at once; without a cap a lucky observation would dominate
 * an entire decay cycle and pin the picker on one (pred -> succ) cell
 * for thousands of iterations.  8 was picked to amplify the obvious
 * tail (most new-edge calls produce 1-2 edges; a handful produce 4-8;
 * outliers can reach hundreds) without letting an outlier set the
 * picker's policy.  The full magnitude is preserved on-wire in
 * struct healer_observation.edge_delta so a future picker can use the
 * unclamped value if a more discriminating amplification model lands.
 */
#define HEALER_EDGE_AMPLIFY_CAP		8U

/*
 * Relation-slot prune threshold, expressed in decay epochs.  A slot
 * whose promoted entries have all decayed to the floor (weight <= 1)
 * AND that hasn't been refreshed by an observation in the last
 * HEALER_PRUNE_EPOCHS decay cycles is cleared so its open-addressing
 * slot becomes available again.  Without pruning, once a distinct
 * predset claims a slot the slot stays claimed forever -- decay can
 * push the weights to 1 but never reclaims the slot, and apply_triple
 * has nowhere to put a new high-value predset whose hash collides
 * into the same probe chain once HEALER_PROBE_LIMIT is exhausted.
 *
 * 4 epochs is the smallest value that still lets a genuinely-useful
 * relation survive a quiet phase: at HEALER_DECAY_INTERVAL_SEC=1800
 * it requires at least ~2 hours of wall time with no observation
 * touching the slot, and at HEALER_DECAY_OBSERVATIONS=5000 it
 * requires ~20K observations elapsed without a refresh.  Either
 * timescale is past the point where the slot is plausibly carrying
 * load; smaller N risks evicting still-useful relations during a
 * temporary lull, larger N lets stale entries clog the probe chain
 * for longer than necessary.
 */
#define HEALER_PRUNE_EPOCHS		4U

/* FNV-1a parameters and packed-key helpers mirror healer.c.  Duplicated
 * rather than hoisted into a shared header to keep the file count down
 * and the dark-launch commit self-contained; the in-shm copies remain
 * authoritative until C3 deletes them. */
#define FNV1A_OFFSET_BASIS 0x811c9dc5U
#define FNV1A_PRIME        0x01000193U

static unsigned int aggregate_predset_hash(unsigned int arch,
					   unsigned int pred_a,
					   unsigned int pred_b)
{
	uint32_t h = FNV1A_OFFSET_BASIS;
	unsigned char buf[sizeof(uint8_t) + sizeof(unsigned int) * 2];
	size_t i;

	/* arch first so the same (pa, pb) under a different arch starts on
	 * a distinct probe chain; one byte is enough headroom -- the enum
	 * has two values today and any future growth fits comfortably. */
	buf[0] = (uint8_t)arch;
	memcpy(buf + 1, &pred_a, sizeof(pred_a));
	memcpy(buf + 1 + sizeof(pred_a), &pred_b, sizeof(pred_b));

	for (i = 0; i < sizeof(buf); i++) {
		h ^= buf[i];
		h *= FNV1A_PRIME;
	}

	if (h == 0)
		h = 1;
	return h;
}

static uint64_t aggregate_pack_key(unsigned int pred_a, unsigned int pred_b,
				   unsigned int predset_hash)
{
	struct {
		uint16_t pa;
		uint16_t pb;
		uint32_t h;
	} tmp = { (uint16_t)pred_a, (uint16_t)pred_b, predset_hash };
	uint64_t packed;

	memcpy(&packed, &tmp, sizeof(packed));
	return packed;
}

static uint64_t aggregate_pack_promoted(unsigned int nr, unsigned int weight)
{
	struct {
		unsigned int n;
		unsigned int w;
	} tmp = { nr, weight };
	uint64_t packed;

	memcpy(&packed, &tmp, sizeof(packed));
	return packed;
}

static void aggregate_unpack_promoted(uint64_t entry, unsigned int *nr,
				      unsigned int *weight)
{
	struct {
		unsigned int n;
		unsigned int w;
	} tmp;

	memcpy(&tmp, &entry, sizeof(tmp));
	*nr = tmp.n;
	*weight = tmp.w;
}

void healer_ring_init(struct healer_ring *ring)
{
	memset(ring->slots, 0, sizeof(ring->slots));
	spsc_ring_init(&ring->base);
}

/*
 * Per-child HEALER reset contract.  Called from clean_childdata() when
 * a child slot is reused so a fresh occupant starts with an empty seq
 * buffer and an empty observation ring rather than inheriting the
 * predecessor's (pred_a, pred_b) window and any pending unfdrained
 * slots.  Without this:
 *   - healer_seq[] / healer_seq_count carry forward from the prior
 *     occupant, so the first observer-hook fire under the new child
 *     attributes its succ to predecessors that ran in a different
 *     process under different fds and a different rng stream;
 *   - the per-child healer_ring inherits the prior occupant's head/tail
 *     cursor, so the first enqueue lands at an arbitrary offset and the
 *     parent's drain reads stale (or wrapped-around) slots.
 * EDGEPAIR_NO_PREV is the documented "no usable predecessor" sentinel:
 * the observer-hook already filters seq slots carrying it (see
 * healer_observe in healer.c), so stamping it on reset keeps any path
 * that reads healer_seq[] before healer_seq_count gates from seeing
 * stale syscall numbers.
 */
void healer_child_reset(struct childdata *child)
{
	if (child == NULL)
		return;

	child->healer_seq[0] = EDGEPAIR_NO_PREV;
	child->healer_seq[1] = EDGEPAIR_NO_PREV;
	child->healer_seq_count = 0;

	if (child->healer_ring != NULL)
		healer_ring_init(child->healer_ring);
}

bool healer_ring_enqueue_observation(struct healer_ring *ring,
				     unsigned int pred_prev,
				     unsigned int pred_last,
				     unsigned int succ,
				     unsigned int succ_arch,
				     unsigned int flags,
				     unsigned int edge_delta,
				     unsigned int result_class)
{
	struct healer_observation slot = {
		.pred_prev = (uint16_t)pred_prev,
		.pred_last = (uint16_t)pred_last,
		.succ = (uint16_t)succ,
		.flags = (uint16_t)flags,
		.edge_delta = (uint16_t)(edge_delta > UINT16_MAX ? UINT16_MAX
								 : edge_delta),
		.result_class = (uint16_t)result_class,
		.succ_arch = (uint16_t)succ_arch,
	};

	if (ring == NULL)
		return false;

	return spsc_ring_try_enqueue(&ring->base, ring->slots,
				     HEALER_RING_SIZE, sizeof(ring->slots[0]),
				     &slot);
}

/*
 * Apply a triple-table update to the canonical relation table.  Single-
 * writer parent context: no CAS, no restart loop, no defensive retry
 * budget.  Bumps pred_appearance for both predecessors (skipping the
 * second on a self-paired predset so the same syscall doesn't get
 * double-counted), walks the open-addressed probe chain looking for the
 * matching predset or an empty slot, then bumps / claims / evicts
 * inside the slot.  weight_inc is the per-observation weight magnitude
 * derived from the call's edge_delta (capped at HEALER_EDGE_AMPLIFY_CAP
 * by the caller) so a bursty edge-rich call contributes proportional
 * weight instead of always bumping by one.
 *
 * The slot key is hashed from the sorted (pred_a, pred_b) tuple so the
 * (A, B) and (B, A) predsets collapse into the same slot; the caller
 * does the sort just before this function runs.
 */
static void apply_triple(unsigned int arch, unsigned int pred_a,
			 unsigned int pred_b, unsigned int succ,
			 unsigned int weight_inc)
{
	unsigned int predset_hash;
	unsigned int slot_idx;
	unsigned int probe;
	unsigned int idx = 0;
	uint64_t target_key;
	struct healer_relation *table = parent_healer.relations;
	struct healer_relation *slot = NULL;
	unsigned int i;
	unsigned int victim_idx = 0;
	unsigned int victim_weight = 0;
	bool victim_found = false;
	bool evicted = false;

	/* A scribbled ring slot can carry any 16-bit value -- bound-check
	 * before indexing.  arch is the successor call's arch dimension;
	 * a scribbled out-of-range value here would index past the
	 * pred_appearance array, so range-gate it too. */
	if (arch >= HEALER_NR_ARCHES ||
	    pred_a >= MAX_NR_SYSCALL || pred_b >= MAX_NR_SYSCALL ||
	    succ >= MAX_NR_SYSCALL)
		return;

	/* Every path past the bounds check mutates persisted state:
	 * pred_appearance bumps below, plus either a relations slot
	 * write (success path) or table_full/relations_observed bumps
	 * (probe-limit path).  Flip once here so the success and
	 * probe-limit branches share one store. */
	healer_snapshot_dirty = true;

	parent_healer.pred_appearance[arch][pred_a]++;
	if (pred_b != pred_a)
		parent_healer.pred_appearance[arch][pred_b]++;

	predset_hash = aggregate_predset_hash(arch, pred_a, pred_b);
	slot_idx = predset_hash & (HEALER_RELATION_SLOTS - 1);
	target_key = aggregate_pack_key(pred_a, pred_b, predset_hash);

	for (probe = 0; probe < HEALER_PROBE_LIMIT; probe++) {
		idx = (slot_idx + probe) & (HEALER_RELATION_SLOTS - 1);

		slot = &table[idx];
		if (slot->key == 0) {
			slot->key = target_key;
			slot->arch = (uint16_t)arch;
			parent_healer.relations_dirty[idx] = 1;
			break;
		}
		if (slot->key == target_key && slot->arch == arch) {
			parent_healer.relations_dirty[idx] = 1;
			break;
		}
	}

	if (probe == HEALER_PROBE_LIMIT) {
		parent_healer.table_full++;
		parent_healer.relations_observed++;
		return;
	}

	/* Phase 1: look for existing (predset, succ) entry, bump it. */
	for (i = 0; i < HEALER_PROMOTED_PER_SLOT; i++) {
		unsigned int weight, nr;

		aggregate_unpack_promoted(slot->promoted[i].entry, &nr, &weight);
		if (weight != 0 && nr == succ) {
			slot->promoted[i].weight += weight_inc;
			goto out;
		}
	}

	/* Phase 2: claim an empty entry. */
	for (i = 0; i < HEALER_PROMOTED_PER_SLOT; i++) {
		if (slot->promoted[i].entry == 0) {
			slot->promoted[i].entry =
				aggregate_pack_promoted(succ, weight_inc);
			goto out;
		}
	}

	/* Phase 3: evict lowest-weight entry.  Inherit victim weight +
	 * weight_inc so a freshly displaced predset isn't instantly re-
	 * evicted on its next observation -- mirrors the in-shm eviction
	 * policy. */
	for (i = 0; i < HEALER_PROMOTED_PER_SLOT; i++) {
		unsigned int weight, nr;

		aggregate_unpack_promoted(slot->promoted[i].entry, &nr, &weight);
		if (!victim_found || weight < victim_weight) {
			victim_idx = i;
			victim_weight = weight;
			victim_found = true;
		}
	}
	slot->promoted[victim_idx].entry =
		aggregate_pack_promoted(succ, victim_weight + weight_inc);
	evicted = true;

out:
	/* Mark the slot as refreshed at the current decay epoch so the
	 * prune walk knows this slot has live observation traffic and
	 * can't be considered stale.  Stamped on every successful
	 * claim/bump/evict; only the probe-limit-overflow path above
	 * skips it (that path doesn't touch a slot at all). */
	parent_healer.relations_last_refreshed[idx] = parent_healer.decay_epoch;
	parent_healer.relations_observed++;
	if (evicted)
		parent_healer.evictions++;
}

/*
 * Apply a pair-table update to the canonical pair table.  Single-
 * writer parent context: increment dynamic_hits by weight_inc with
 * saturation clamp at HEALER_PAIR_MAX_WEIGHT, mirrors the in-shm
 * path's CAS loop without the loop.  Leaves static_prior untouched --
 * the seed is a stable metadata fact about the pair, distinct from
 * the runtime observation evidence accumulating on top of it.  Stamps
 * last_observed_epoch so the pair-table prune walk (follow-up commit)
 * can tell live cells from quiet ones.
 *
 * weight_inc is the per-observation magnitude derived from the call's
 * edge_delta (capped at HEALER_EDGE_AMPLIFY_CAP by the caller).
 */
static void apply_pair(unsigned int arch, unsigned int pred, unsigned int succ,
		       unsigned int weight_inc)
{
	struct healer_pair_cell *cell;
	uint32_t hits, new_hits;

	if (arch >= HEALER_NR_ARCHES ||
	    pred >= MAX_NR_SYSCALL || succ >= MAX_NR_SYSCALL)
		return;

	cell = &parent_healer.pair_table[arch][pred][succ];
	hits = cell->dynamic_hits;
	if (hits >= HEALER_PAIR_MAX_WEIGHT)
		return;

	new_hits = hits + weight_inc;
	if (new_hits > HEALER_PAIR_MAX_WEIGHT || new_hits < hits)
		new_hits = HEALER_PAIR_MAX_WEIGHT;
	cell->dynamic_hits = new_hits;
	cell->last_observed_epoch = parent_healer.decay_epoch;
	parent_healer.pair_dirty[arch][pred] = 1;
	healer_snapshot_dirty = true;
}

/*
 * Convert the on-wire edge_delta to a bounded weight increment.  A new-
 * edge observation always counts for at least one bump (the historical
 * "one event = one increment" semantic); a bursty observation that
 * uncovered N bucket edges contributes min(N, HEALER_EDGE_AMPLIFY_CAP)
 * so an outlier can't pin the picker on a single (pred -> succ) cell
 * for thousands of iterations.  See HEALER_EDGE_AMPLIFY_CAP for the
 * rationale on the cap value.
 */
static unsigned int healer_edge_weight_inc(uint16_t edge_delta)
{
	unsigned int w = edge_delta;

	if (w == 0)
		w = 1;
	if (w > HEALER_EDGE_AMPLIFY_CAP)
		w = HEALER_EDGE_AMPLIFY_CAP;
	return w;
}

/*
 * Drive both the pair-table and triple-table updates from one unified
 * observation slot.  pred_last is the immediate predecessor (drives
 * the pair update); pred_prev is the syscall before that (combined
 * with pred_last to drive the triple update when populated).  Either
 * predecessor missing is signalled by EDGEPAIR_NO_PREV; pair updates
 * still fire as long as pred_last is valid.  Sort happens here at
 * apply time so the on-wire slot preserves chronological ordering for
 * downstream consumers that want it.
 */
static void apply_observation(const void *p, void *ctx __unused__)
{
	const struct healer_observation *obs = p;
	unsigned int weight_inc;
	unsigned int pred_prev, pred_last, succ, arch;

	pred_prev = obs->pred_prev;
	pred_last = obs->pred_last;
	succ = obs->succ;
	arch = obs->succ_arch;

	/* succ is always required.  pred_last must be valid for either
	 * update; without it there is no relation to learn from this
	 * observation.  arch is the successor's arch dim (clamped to
	 * HEALER_NR_ARCHES at enqueue is the producer's responsibility,
	 * but bounds-check defensively too). */
	if (succ >= MAX_NR_SYSCALL)
		return;
	if (pred_last == EDGEPAIR_NO_PREV)
		return;
	if (arch >= HEALER_NR_ARCHES)
		return;

	weight_inc = healer_edge_weight_inc(obs->edge_delta);

	apply_pair(arch, pred_last, succ, weight_inc);

	if (pred_prev != EDGEPAIR_NO_PREV) {
		unsigned int pa = pred_prev;
		unsigned int pb = pred_last;

		if (pa > pb) {
			unsigned int tmp = pa;
			pa = pb;
			pb = tmp;
		}
		apply_triple(arch, pa, pb, succ, weight_inc);
	}
}

unsigned int healer_ring_drain(struct healer_ring *ring)
{
	uint32_t overflow = 0;
	uint32_t processed;

	if (ring == NULL)
		return 0;

	processed = spsc_ring_drain(&ring->base, ring->slots,
				    HEALER_RING_SIZE, sizeof(ring->slots[0]),
				    apply_observation, NULL, &overflow);
	parent_healer.ring_overflow_total += overflow;
	return processed;
}

/*
 * Decay one (pred -> succ) row of the pair table in place.  Halves
 * every cell's dynamic_hits above the floor and reports whether
 * anything changed so the caller can flip the row's dirty bit for the
 * next publish.
 *
 * Touches dynamic_hits only.  static_prior is the static-metadata
 * fact about the (producer, consumer) pair and carries no decay
 * semantics: a kernel that exposes a producer/consumer relation today
 * still exposes it after an hour of quiet runtime, so attenuating the
 * prior would deprive the cold-start picker of its bootstrap signal
 * the longer the run goes.  dynamic_hits, by contrast, is the
 * runtime-evidence half and SHOULD relax during quiet phases so a
 * pair that has stopped firing recently loses its picker-side
 * advantage to fresher signal.
 */
static bool healer_decay_pair_row(unsigned int arch, unsigned int pred)
{
	bool row_modified = false;
	unsigned int succ;

	for (succ = 0; succ < MAX_NR_SYSCALL; succ++) {
		struct healer_pair_cell *cell;
		uint32_t hits;

		cell = &parent_healer.pair_table[arch][pred][succ];
		hits = cell->dynamic_hits;
		if (hits <= 1)
			continue;

		cell->dynamic_hits = hits / 2;
		row_modified = true;
	}
	return row_modified;
}

/*
 * Parent-side decay walk.  Same trigger pair as the in-shm path
 * (observation count + wall-clock) but evaluated against parent-
 * private counters during drain.  No CAS election (single writer).
 * Marks the entire relation table dirty on a real decay so the next
 * publish propagates the halved weights.  Same trigger fires the
 * pair-table decay so both tables age in lockstep -- without that,
 * long-running fuzzes (or runs warm-started from a saturated
 * snapshot) leave the pair table holding stale weights that no live
 * observation ever displaces, since apply_pair only saturates
 * upward.  decay_epoch advances by one on every fire and is the
 * reference clock for the per-slot prune logic the next commit
 * builds on top.
 */
static void healer_apply_maybe_decay(void)
{
	unsigned long obs_now = parent_healer.relations_observed;
	unsigned long old_obs = parent_healer.obs_at_last_decay;
	unsigned long now_sec = (unsigned long)time(NULL);
	unsigned long old_time = parent_healer.time_at_last_decay;
	bool obs_trigger, time_trigger;
	unsigned int i, j;
	bool any_dirty = false;

	obs_trigger = (obs_now >= old_obs + HEALER_DECAY_OBSERVATIONS);
	time_trigger = (now_sec >= old_time + HEALER_DECAY_INTERVAL_SEC);

	if (!obs_trigger && !time_trigger)
		return;

	/* Past the trigger gate every branch below mutates persisted
	 * header state (obs_at_last_decay / time_at_last_decay / decay_epoch
	 * / weight_decays_run) at minimum, and typically prunes/halves a
	 * handful of relation and pair-table entries on top of that. */
	healer_snapshot_dirty = true;

	parent_healer.obs_at_last_decay = obs_now;
	parent_healer.time_at_last_decay = now_sec;

	for (i = 0; i < HEALER_RELATION_SLOTS; i++) {
		struct healer_relation *slot = &parent_healer.relations[i];
		bool slot_at_floor;
		uint16_t age;

		if (slot->key == 0)
			continue;

		for (j = 0; j < HEALER_PROMOTED_PER_SLOT; j++) {
			unsigned int weight, nr, halved;

			aggregate_unpack_promoted(slot->promoted[j].entry,
						  &nr, &weight);
			if (weight <= 1)
				continue;

			halved = weight / 2;
			if (halved < 1)
				halved = 1;
			slot->promoted[j].weight = halved;
			any_dirty = true;
		}
		if (any_dirty)
			parent_healer.relations_dirty[i] = 1;

		/* Prune-eligibility: every populated promoted entry decayed
		 * down to the floor AND no apply_triple has stamped this
		 * slot's last_refreshed in HEALER_PRUNE_EPOCHS or more
		 * cycles.  Clearing key + promoted releases the slot back
		 * to the open-addressing pool so an incoming high-value
		 * predset whose hash collided here can claim it on the
		 * next observation.  uint16_t subtraction is wrap-safe at
		 * the small distances the comparison cares about (a slot
		 * stale enough to prune is by definition not within
		 * 65535-HEALER_PRUNE_EPOCHS epochs of decay_epoch). */
		slot_at_floor = true;
		for (j = 0; j < HEALER_PROMOTED_PER_SLOT; j++) {
			unsigned int weight, nr;

			aggregate_unpack_promoted(slot->promoted[j].entry,
						  &nr, &weight);
			if (weight > 1) {
				slot_at_floor = false;
				break;
			}
		}
		age = (uint16_t)(parent_healer.decay_epoch -
				 parent_healer.relations_last_refreshed[i]);
		if (slot_at_floor && age >= HEALER_PRUNE_EPOCHS) {
			memset(slot, 0, sizeof(*slot));
			parent_healer.relations_last_refreshed[i] = 0;
			parent_healer.relations_dirty[i] = 1;
		}
	}

	{
		unsigned int a;
		for (a = 0; a < HEALER_NR_ARCHES; a++) {
			for (i = 0; i < MAX_NR_SYSCALL; i++) {
				if (healer_decay_pair_row(a, i))
					parent_healer.pair_dirty[a][i] = 1;
			}
		}
	}

	parent_healer.decay_epoch++;
	parent_healer.weight_decays_run++;
}

/*
 * Publish dirty rows of both tables to the mirror pages.  Caller must
 * have already thawed the global-obj freeze.  Walks the dirty bitmaps
 * once, clears each set bit as the row is copied.  Steady-state cost
 * is dominated by the bitmap scan; the actual memcpy is small.
 */
static void healer_publish_locked(void)
{
	unsigned int i;

	if (healer_relations_published != NULL) {
		for (i = 0; i < HEALER_RELATION_SLOTS; i++) {
			if (!parent_healer.relations_dirty[i])
				continue;
			healer_relations_published[i] =
				parent_healer.relations[i];
			parent_healer.relations_dirty[i] = 0;
		}
	}

	if (healer_pair_published != NULL) {
		unsigned int a;
		for (a = 0; a < HEALER_NR_ARCHES; a++) {
			for (i = 0; i < MAX_NR_SYSCALL; i++) {
				if (!parent_healer.pair_dirty[a][i])
					continue;
				memcpy(healer_pair_published[a][i],
				       parent_healer.pair_table[a][i],
				       sizeof(parent_healer.pair_table[a][i]));
				parent_healer.pair_dirty[a][i] = 0;
			}
		}
	}

	/* Mirror-integrity sample.  After the publish completes the
	 * mirror's first relation slot and pair-table cell should match
	 * the canonical's; the only thing that could write to the mirror
	 * between publishes is a wild kernel store, and the PROT_READ
	 * mprotect should SEGV that in the offending child instead.  A
	 * non-zero published_corrupt counter implies either a hole in
	 * the freeze/thaw bracket or a wild store that somehow bypassed
	 * the read-only mapping -- log + count, same shape as Stage 1's
	 * shm_published_corrupt mirror integrity check. */
	if (healer_relations_published != NULL &&
	    healer_relations_published[0].key !=
		parent_healer.relations[0].key)
		parent_healer.published_corrupt++;
	if (healer_pair_published != NULL &&
	    memcmp(&healer_pair_published[0][0][0],
		   &parent_healer.pair_table[0][0][0],
		   sizeof(struct healer_pair_cell)) != 0)
		parent_healer.published_corrupt++;
}

void healer_ring_drain_all(void)
{
	unsigned int i;

	if (children == NULL)
		return;

	for_each_child(i) {
		struct childdata *child;
		struct healer_ring *ring;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;

		ring = __atomic_load_n(&child->healer_ring, __ATOMIC_ACQUIRE);
		if (ring == NULL)
			continue;

		(void) healer_ring_drain(ring);
	}

	healer_apply_maybe_decay();
	healer_publish_locked();
	/* Snapshot trigger evaluated against parent-private counters and
	 * fired from drain context (single writer); save-file is a normal
	 * sequential call from here, no CAS election needed. */
	healer_maybe_snapshot();
}

void healer_published_init(void)
{
	healer_relations_published = alloc_shared(
		sizeof(struct healer_relation) * HEALER_RELATION_SLOTS);
	memset(healer_relations_published, 0,
	       sizeof(struct healer_relation) * HEALER_RELATION_SLOTS);

	healer_pair_published = alloc_shared(
		sizeof(struct healer_pair_cell) * HEALER_NR_ARCHES *
		MAX_NR_SYSCALL * MAX_NR_SYSCALL);
	memset(healer_pair_published, 0,
	       sizeof(struct healer_pair_cell) * HEALER_NR_ARCHES *
	       MAX_NR_SYSCALL * MAX_NR_SYSCALL);
}

/*
 * Per-child mprotect freeze of the HEALER mirror pages.  The two
 * published mirrors are intended parent-write / child-read (the picker
 * in child context reads relations + pair weights through these pages;
 * the parent's drain is the sole writer).  The mirror-integrity sample
 * at the bottom of healer_publish_locked() documents the PROT_READ
 * contract -- "the only thing that could write to the mirror between
 * publishes is a wild kernel store, and the PROT_READ mprotect should
 * SEGV that in the offending child instead" -- but the matching
 * mprotect() call was missing, leaving the contract as comment only.
 *
 * Called from the per-child post-fork init hook so the freeze applies
 * in child address space.  mprotect is per-process, so the parent's
 * mapping stays PROT_READ|PROT_WRITE and the drain's publish keeps
 * writing through; only children see the read-only view.
 *
 * Best-effort on failure: log via the canonical helper and continue.
 * mprotect can ENOMEM if the kernel runs out of VMA slots splitting
 * the mapping that backs the mirror (same failure mode as the
 * freeze_sibling_childdata sweep) and turning a transient kernel limit
 * into a fleet-wide crash would be worse than leaving the mirror RW
 * for the lifetime of the affected child.
 */
void healer_published_freeze(void)
{
	size_t bytes;

	if (healer_relations_published != NULL) {
		bytes = sizeof(struct healer_relation) * HEALER_RELATION_SLOTS;
		bytes = (bytes + page_size - 1) & PAGE_MASK;
		if (mprotect(healer_relations_published, bytes, PROT_READ) != 0)
			log_mprotect_failure(healer_relations_published, bytes,
					     PROT_READ,
					     __builtin_return_address(0), errno);
	}

	if (healer_pair_published != NULL) {
		bytes = sizeof(struct healer_pair_cell) * HEALER_NR_ARCHES *
			MAX_NR_SYSCALL * MAX_NR_SYSCALL;
		bytes = (bytes + page_size - 1) & PAGE_MASK;
		if (mprotect(healer_pair_published, bytes, PROT_READ) != 0)
			log_mprotect_failure(healer_pair_published, bytes,
					     PROT_READ,
					     __builtin_return_address(0), errno);
	}
}

void healer_aggregate_pair_set(unsigned int arch, unsigned int pred,
			       unsigned int succ, unsigned int weight)
{
	struct healer_pair_cell *cell;

	if (arch >= HEALER_NR_ARCHES ||
	    pred >= MAX_NR_SYSCALL || succ >= MAX_NR_SYSCALL)
		return;

	cell = &parent_healer.pair_table[arch][pred][succ];

	/* Idempotent: a previous loader call already installed a prior
	 * here -- skip silently rather than overwriting an authoritative
	 * existing value.  Independent of dynamic_hits, since the static
	 * prior is metadata-derived and a runtime observation never
	 * conjures one up.  Clamp at the uint8_t field width; callers
	 * pass HEALER_STATIC_SEED_WEIGHT (currently 3) but a future
	 * re-tuning that overflows uint8_t should saturate visibly rather
	 * than silently truncate. */
	if (cell->static_prior != 0)
		return;

	if (weight > UINT8_MAX)
		weight = UINT8_MAX;
	cell->static_prior = (uint8_t)weight;
	parent_healer.pair_dirty[arch][pred] = 1;
	parent_healer.pair_seeded++;
	healer_snapshot_dirty = true;
}
