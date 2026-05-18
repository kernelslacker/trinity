#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "arch.h"	/* ARCH_IS_BIARCH */

/*
 * HEALER arch dimension.  Pair and triple keys are indexed by the
 * successor call's arch so a (pred, succ) cell observed under a 64-bit
 * successor doesn't collide with the same numeric pair under a 32-bit
 * successor on biarch builds (where the 32-bit and 64-bit syscall
 * tables map the same raw nr to different syscalls).  On uniarch builds
 * the dimension collapses to a constant 1 -- the per-cell footprint and
 * picker-side indexing cost are identical to the pre-arch layout, and
 * the picker's previous biarch-fallback comment goes away because the
 * picker can index the arch dimension directly.
 *
 * HEALER_ARCH_64 is the do-not-care fallback on uniarch (every cell
 * lands at arch=0 regardless of compile-time word size).  HEALER_ARCH_32
 * is defined only on biarch so callers that mention it on uniarch fail
 * to compile rather than silently picking the wrong cell.
 */
#ifdef ARCH_IS_BIARCH
#define HEALER_NR_ARCHES	2U
#define HEALER_ARCH_64		0U
#define HEALER_ARCH_32		1U
#else
#define HEALER_NR_ARCHES	1U
#define HEALER_ARCH_64		0U
#endif

/*
 * Map a do32 flag to the arch dimension index.  Returns HEALER_ARCH_64
 * on uniarch unconditionally (HEALER_NR_ARCHES == 1 collapses every
 * call to the single slot).  On biarch the picker's choose_syscall_table
 * decision and the seed loader's per-table walk both feed do32 through
 * here so the indexing convention stays in one place.
 */
static inline unsigned int healer_arch_id(bool do32)
{
#ifdef ARCH_IS_BIARCH
	return do32 ? HEALER_ARCH_32 : HEALER_ARCH_64;
#else
	(void)do32;
	return HEALER_ARCH_64;
#endif
}

/*
 * HEALER syscall-relation observer (Phase A: instrumentation only).
 *
 * Inspired by the HEALER design from kernel-fuzzing literature:
 * a syscall sequence whose execution drives kcov to a NEW PC edge that
 * neither member alone could reach implies a learned dependence between
 * the predecessor syscalls and the syscall that closed the loop.  Over
 * many such observations we accumulate a relation graph
 * `{pred_a, pred_b} -> nr` weighted by the number of new-edge events
 * each (predset, promoted_nr) tuple was credited with.
 *
 * Phase A is purely an observer.  No bandit arm consumes the table,
 * the syscall picker has no awareness of it, and there is no CLI flag.
 * The intent is to collect data for an operator review window so we can
 * sanity-check that the relations the observer learns look plausible
 * before authorising the picker work in Phase B (which will introduce a
 * STRATEGY_HEALER arm that biases picks toward (predset -> nr) edges
 * with the highest accumulated weight).
 *
 * Predecessor sequence depth is fixed at 2 (the immediately-preceding
 * two completed syscalls); the predset is stored in CHRONOLOGICAL
 * order (pred_a = pred_prev, pred_b = pred_last) so (A, B) and (B, A)
 * occupy distinct slots and the direction-asymmetric kernel-causal
 * relations they encode stay separate.  Lookup is open-addressing
 * over an FNV-1a hash of the (arch, pred_a, pred_b) tuple; collisions
 * linear-probe up to HEALER_PROBE_LIMIT slots.  Inside each predset
 * slot a small dense array tracks up to HEALER_PROMOTED_PER_SLOT
 * promoted syscalls, evicting the lowest-weight entry when full.
 */

/*
 * Power-of-two table size keeps the slot index a cheap mask of the
 * hash output.  Bumped from 16384 to 32768 when the triple key flipped
 * from sorted to chronological order: (A, B) and (B, A) used to share
 * a slot but now occupy distinct slots, so the steady-state distinct-
 * predset count under realistic workloads can roughly double.  At 80
 * bytes per slot the table is now 2.5 MiB (was 1.25 MiB), still well
 * inside the per-arena budget (cmp_novelty[] alone is ~132 KiB,
 * frontier_history[] another 32 KiB).
 */
#define HEALER_RELATION_SLOTS    32768

/*
 * Per-predset cap on the number of (promoted_nr) entries we track.
 * 8 was picked empirically: most useful relations cluster on a small
 * tail of follow-ups; an overflow in production triggers the lowest-
 * weight eviction (mirroring corrupt_ptr_attr_record's policy) so
 * surprise late-arriving high-weight follow-ups can still displace
 * stale low-weight ones without a full table scan.
 */
#define HEALER_PROMOTED_PER_SLOT 8

/*
 * Open-addressing probe limit.  A short cap bounds the worst-case
 * lookup cost under heavy collision load; if the probe runs off the
 * end of the cap without finding either the matching predset or an
 * empty slot, the observation is dropped and parent_healer.table_full
 * is bumped so the operator can spot a saturated table.  16 slots is
 * a reasonable compromise: with 16K slots and a 50%-full table the
 * expected probe length is ~2, so 16 leaves ample headroom for the
 * worst-case high-load tail.
 */
#define HEALER_PROBE_LIMIT       16

/*
 * One promoted-syscall entry inside a relation slot.  The (nr, weight)
 * pair lives in a 64-bit union so observers can CAS-claim a fresh
 * entry, atomic-fetch-add an existing entry's weight, and CAS-evict
 * the lowest-weight entry, all without serialising through a per-slot
 * lock.  weight == 0 is the empty-entry sentinel: real entries are
 * inserted with weight == 1 and only ever ratchet up or get replaced
 * wholesale by an eviction CAS, so weight never transiently reads
 * back as 0 once an entry has been published.
 */
struct healer_promoted {
	union {
		struct {
			unsigned int nr;
			unsigned int weight;	/* edge-discovery count attributed to this
						 * (predset, nr) tuple. */
		};
		uint64_t entry;
	};
};

/*
 * One relation-table slot.  The leading (pred_a, pred_b, predset_hash)
 * tuple is laid out so a single 64-bit load through the `key` union
 * member sees a coherent identifier triple in one memory access,
 * mirroring edgepair_entry's packed-key shape in edgepair.c.
 * `predset_hash == 0` (and therefore `key == 0`) is the empty-slot
 * sentinel; healer_predset_hash() remaps the vanishingly rare FNV-1a
 * output of 0 to 1 so a real predset never collides with empty,
 * leaving the surrounding aggregate memset(0) as the only
 * initialisation the table needs.  pred_a and pred_b are stored in
 * CHRONOLOGICAL order (pred_a is two completed syscalls back,
 * pred_b is one back) so the (A, B) and (B, A) chains stay
 * direction-distinct; they are narrowed to uint16_t -- syscall numbers
 * fit (MAX_NR_SYSCALL is 1024) and the caller already filters the
 * EDGEPAIR_NO_PREV (0xFFFF) sentinel before we ever reach a slot.
 *
 * `arch` carries the successor call's arch dimension (0..HEALER_NR_ARCHES
 * -1; see healer_arch_id above).  The same numeric (pred_a, pred_b)
 * pair under a different arch hashes to a different probe-chain start
 * via healer_predset_hash(arch, pa, pb), and a slot match on the chain
 * requires both .key AND .arch to agree -- so a biarch host that maps
 * the same raw syscall numbers to different syscalls in its 32-bit and
 * 64-bit tables no longer collapses both arches onto one shared slot.
 * On uniarch builds HEALER_NR_ARCHES == 1 and arch is always 0, with
 * zero memory/runtime cost vs the pre-arch layout.
 *
 * The 8-byte arch chunk (arch + padding) sits AFTER the 8-byte packed
 * key so the original packed-key offset asserts in healer.c stay
 * valid; total slot header is 16 bytes (was 8), and the on-disk
 * persistence format bumps to v3 with this commit to reflect the new
 * layout (a v2 file is auto-rejected at load by the version check).
 */
struct healer_relation {
	union {
		struct {
			uint16_t pred_a;
			uint16_t pred_b;
			uint32_t predset_hash;
		};
		uint64_t key;
	};
	uint16_t arch;
	uint16_t _pad0;
	uint32_t _pad1;
	struct healer_promoted promoted[HEALER_PROMOTED_PER_SLOT];
};

struct childdata;

/*
 * Reserved flag bits for healer_observe()'s flags argument.  Carried
 * on the on-wire observation slot for downstream consumers; the
 * parent's apply path doesn't branch on them today.
 */
#define HEALER_OBS_FLAG_EXPLORER	(1U << 0)	/* fired from an explorer-pool child */

/*
 * Observer hook fired on the new-edge branch of dispatch_step (and only
 * the new-edge branch -- the cost has to stay zero on the syscall hot
 * path).  Reads the child's last-2 completed syscall numbers out of
 * the per-child sequence buffer and enqueues a single unified
 * observation slot carrying both predecessors (in chronological order,
 * NOT sorted), the new-edge succ, the call's bucket-edge count from
 * kcov_collect (for weight amplification at apply time), and reserved
 * flags / result-class fields.  The parent's drain applies both the
 * pair-table bump (pred_last -> succ) AND the triple-table bump
 * (sort(pred_prev, pred_last) -> succ) from the same slot under
 * single-writer discipline.
 *
 * `do32` is the SUCCESSOR call's arch -- the predecessor's arch is not
 * tracked because the pair and triple tables index by the successor's
 * arch dimension (see struct healer_relation::arch and the per-arch
 * pair_table layout in struct healer_aggregate).  On uniarch builds
 * do32 collapses to a no-op through healer_arch_id().
 *
 * Drops the observation when no predecessor is available (the very
 * first syscall of a child's life, or a child whose seq buffer was
 * just reset).  Triple-table updates additionally require both
 * predecessor slots populated; pair-table updates only need pred_last.
 */
void healer_observe(struct childdata *child, unsigned int current_nr,
		    bool do32, unsigned int flags, unsigned int edge_delta,
		    unsigned int result_class);

/*
 * Push the just-completed syscall nr onto the child's per-child
 * sequence buffer.  Called from the per-call bookkeeping path right
 * after the child's last_syscall_nr update so the next call's
 * observer-hook fire sees the correct two predecessors.
 */
void healer_seq_push(struct childdata *child, unsigned int nr);

/*
 * Periodic dump emitted alongside defense_counters_periodic_dump and
 * corrupt_ptr_attr_dump.  Sweeps the relation table to compute occupancy
 * and total promoted-entry count, then prints the top 10 relations
 * by (predset, promoted_nr) weight so the operator can sanity-check
 * what the observer is learning without waiting for end-of-run.
 *
 * Output goes through stats_log_write() so it mirrors to the
 * --stats-log-file=PATH file when configured, matching the convention
 * established for the defense counter dump.
 */
void healer_table_dump(void);

/*
 * Cross-run persistence.  Serialise the parent_healer.relations table
 * to `path` (atomic via tmp-file + rename) so a subsequent run can
 * warm-start from it.  Returns true on success; on failure the
 * destination file is left untouched.  Runs from parent drain context
 * (single writer), so no concurrent-observer staging is needed.
 */
bool healer_save_file(const char *path);

/*
 * Reverse of healer_save_file().  Stages the file payload through a
 * heap buffer, validates the header (magic, version, table dimensions,
 * MAX_NR_SYSCALL, kernel utsname.release/.version) and the payload
 * CRC32, then bulk-copies into parent_healer.relations and restores
 * parent_healer.relations_observed / .obs_at_last_snapshot.  Caller
 * must invoke pre-fork from the parent so the first drain after fork
 * has the populated canonical to publish to the mirror.  Returns true
 * on a successful warm-start; a kernel-utsname mismatch logs a one-line
 * cold-start notice and returns false.
 */
bool healer_load_file(const char *path);

/*
 * Build a default per-arch relation-table path under
 * $XDG_CACHE_HOME/trinity/healer/<arch>-<release> (or
 * $HOME/.cache/...).  Creates the parent directory tree on demand;
 * returns NULL on uname() failure or path-buffer overflow.  Mirrors
 * minicorpus_default_path() and effector_map_default_path().
 */
const char *healer_default_path(void);

/*
 * Configure the path that healer_maybe_snapshot() will save to.  Must
 * be called in the parent before fork so children inherit
 * healer_snapshot_path COW.  No-op on NULL or oversized path.
 */
void healer_enable_snapshots(const char *path);

/*
 * Periodic mid-run snapshot trigger.  Cheap fast path when the fleet-
 * wide observation count hasn't advanced HEALER_SNAPSHOT_OBSERVATIONS
 * past the last snapshot's high-water-mark.  When the gap is reached,
 * one CAS-elected caller runs healer_save_file() to the configured
 * path; everyone else loses the CAS and returns.  Called from the
 * parent drain context now (see healer_ring_drain_all()).
 */
void healer_maybe_snapshot(void);

/*
 * Pair-relation table -- single-predecessor companion to the
 * (predset -> nr) triple table above.  Indexed (pred -> succ); each
 * cell is a struct healer_pair_cell that separately tracks the static
 * prior (metadata-derived bootstrap), runtime dynamic_hits
 * (accumulated runtime evidence), and last_observed_epoch (decay
 * clock).  Decay halves dynamic_hits only -- the static prior is
 * stable, so a long quiet phase relaxes the dynamic signal without
 * erasing the bootstrap beneath it.  The canonical lives in
 * parent_healer.pair_table (parent-private, fed by the per-child
 * healer_ring observer events the drain applies under single-writer
 * discipline); the picker reads its values through the published
 * mirror page (healer_pair_published).  See include/healer_ring.h
 * for the retrofit topology and the cell layout.
 *
 * Bootstrapped from a static (producer -> consumer) prior derived from
 * existing ARG_FD_* / ret_objtype metadata via healer_load_static_seed(),
 * then refined at runtime by the unified healer_observe() firing on
 * the new-edge path -- the same slot drives both the pair-table and
 * triple-table updates.  Pairs are coarser-grained than the triples
 * but converge MUCH faster from a static prior than triples can.
 *
 * The accessors silently no-op (or, for read accessors, return 0)
 * when either syscall number is out of range, so callers don't have
 * to gate on MAX_NR_SYSCALL themselves.
 */
void healer_pair_seed(unsigned int arch, unsigned int pred, unsigned int succ,
		      unsigned int weight);

/*
 * Combined picker weight for an (arch, pred -> succ) cell: static prior
 * (carries the metadata-derived bootstrap signal) plus the runtime
 * dynamic_hits accumulator.  Returned as a single value so the picker's
 * existing distribution-build loop stays a single load per candidate.
 * Reads through the published mirror page; bounded staleness (~ms per
 * drain) is operationally indistinguishable from fresh.  arch is the
 * successor's arch dimension (see healer_arch_id); on uniarch the
 * argument is unused and always indexes the single slot.
 */
unsigned int healer_pair_get(unsigned int arch, unsigned int pred,
			     unsigned int succ);

/*
 * Dynamic-hits component for an (arch, pred -> succ) cell.  Used by
 * callers that need to reason about runtime evidence specifically,
 * separately from the static prior -- the eligibility gate (which
 * would otherwise count bare seeds as evidence) and the dump path
 * (which routes cells to the seed-only vs dynamically-confirmed
 * pools).  Returns 0 if the mirror page is not yet allocated or the
 * indices are out of range, matching healer_pair_get's defensive
 * shape.
 */
unsigned int healer_pair_dynamic_hits(unsigned int arch, unsigned int pred,
				      unsigned int succ);

/*
 * Static-seed classifier dry-run.  Walks the active syscall table once
 * and counts the (producer, consumer) pairs that match by metadata --
 * specifically, syscalls whose ret_objtype matches another syscall's
 * typed-fd argtype slot.  Returns the count without writing anything;
 * the seed loader that bulk-populates healer_pair_seed() from the same
 * walk is a separate follow-up commit, and this counter exists so the
 * classifier's edge inventory can be sanity-checked in isolation
 * before the loader starts mutating the pair table.
 */
unsigned int healer_count_pc_pairs(void);

/*
 * Static-seed loader.  Walks the active syscall table(s) at startup
 * and pre-populates the pair table by calling healer_pair_seed() with
 * HEALER_STATIC_SEED_WEIGHT for every (producer, consumer) edge that
 * the same metadata walked by healer_count_pc_pairs() identifies.
 * Run once pre-fork from the trinity init path so children inherit
 * the populated pair table by COW.  Returns the number of fresh CAS-
 * successful seed installs (cells that went from 0 to the seed weight
 * during this call); cells already populated by an earlier observation
 * or a previous loader invocation are silently skipped.  Idempotent.
 */
unsigned int healer_load_static_seed(void);

/*
 * Three-way classification of HEALER readiness.
 *
 *   HEALER_NOT_READY        -- pair table carries neither enough dynamic
 *                              evidence nor any static seeds, so the
 *                              picker has nothing useful to bias from.
 *   HEALER_READY_SEED_ONLY  -- static seeds are present (i.e. the static
 *                              prior loader has run) but the runtime
 *                              observer has not yet confirmed enough
 *                              cells to clear the dynamic threshold.
 *                              Not eligible under the strict gate, but
 *                              eligible under a plateau bypass and
 *                              useful to surface in the operator dump.
 *   HEALER_READY_DYNAMIC    -- enough cells have crossed the per-cell
 *                              dynamic-hits floor to score the arm
 *                              against uniform random honestly.  This
 *                              is the only state that satisfies the
 *                              non-bypassed gate.
 */
enum healer_readiness {
	HEALER_NOT_READY,
	HEALER_READY_SEED_ONLY,
	HEALER_READY_DYNAMIC,
};

/*
 * STRATEGY_HEALER readiness gate (strict).  Returns true only when the
 * pair table has accumulated enough RUNTIME evidence to be worth
 * scheduling the arm: a fixed minimum number of cells whose
 * dynamic_hits crosses the per-cell evidence floor.  Bare static seeds
 * do NOT satisfy this gate -- a freshly seeded pair carries no runtime
 * evidence, and the previous combined-weight gate let those seeds trip
 * a cold table.
 *
 * Owned by the healer module so the readiness decision sits next to
 * the encoding it reads (struct healer_pair_cell's static_prior /
 * dynamic_hits split).  Callers above the picker only see the boolean
 * verdict; the threshold itself is an internal tuning knob.
 *
 * Cheap to call: bounded scan of the pair table with early-out once
 * the threshold is hit or the scan cap is reached.  See
 * healer_strategy_ready_explicit() for the seed-only vs dynamic
 * distinction the operator dump surfaces, and
 * healer_strategy_ready_plateau_bypass() for the looser variant the
 * plateau-intervention path uses.
 */
bool healer_strategy_ready(void);

/*
 * Diagnostic variant of the readiness gate.  Returns true if the table
 * has any usable signal at all (HEALER_READY_SEED_ONLY or
 * HEALER_READY_DYNAMIC) and stamps *out with which.  Used by the dump
 * path to print 'HEALER eligible (seed only)' vs 'HEALER eligible
 * (dynamic)' so the operator can tell whether the strict gate has
 * fired or only the static prior is carrying the signal.  *out is
 * always stamped (HEALER_NOT_READY when the return is false), so
 * callers can read it unconditionally.
 */
bool healer_strategy_ready_explicit(enum healer_readiness *out);

/*
 * Plateau-bypass variant.  Returns true if the pair table carries ANY
 * content -- a static seed or a runtime hit -- without insisting on
 * the strict dynamic-evidence threshold.  Used by the plateau
 * intervention path: when kcov reports the fleet is stalled, any
 * signal that nudges the bandit off the current local minimum is
 * worth scheduling, even one whose evidence base is thin.  An
 * entirely-empty table still returns false: the picker would only
 * fall back to uniform random in that case, which the intervention
 * path can pick directly without going through HEALER.
 */
bool healer_strategy_ready_plateau_bypass(void);

struct syscallrecord;

/*
 * STRATEGY_HEALER picker (Phase B).  Builds a per-call weighted
 * distribution over the active syscall table from the pair-relation
 * table indexed by the child's most-recent predecessor, optionally
 * augmented by the triple-relation table when the child has both
 * predecessor slots populated.  Falls back to set_syscall_nr_random()
 * on cold-start (no predecessor recorded yet), zero-weight (the
 * predecessor has no recorded productive relations), or any
 * downstream validation/EXPENSIVE-skip dead-end.  Returns the same
 * true/FAIL convention as the other set_syscall_nr_* variants so the
 * dispatch in random-syscall.c can switch on it uniformly.
 */
bool set_syscall_nr_healer(struct syscallrecord *rec, struct childdata *child);
