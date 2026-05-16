#pragma once

#include <stdint.h>

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
 * two completed syscalls); the predset is sorted before hashing so
 * (A, B) and (B, A) collapse into one slot.  Lookup is open-addressing
 * over an FNV-1a hash of the sorted (pred_a, pred_b) tuple; collisions
 * linear-probe up to HEALER_PROBE_LIMIT slots.  Inside each predset
 * slot a small dense array tracks up to HEALER_PROMOTED_PER_SLOT
 * promoted syscalls, evicting the lowest-weight entry when full.
 */

/*
 * Power-of-two table size keeps the slot index a cheap mask of the
 * hash output.  16384 slots * 72 bytes per slot ~= 1.13 MiB of shm,
 * well within the existing per-arena budget (cmp_novelty[] alone is
 * ~132 KiB, frontier_history[] another 32 KiB).
 */
#define HEALER_RELATION_SLOTS    16384

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
 * tuple is laid out so a single 64-bit atomic load/CAS through the
 * `key` union member sees a coherent identifier triple, mirroring
 * edgepair_entry's packed-key claim protocol in edgepair.c.
 * `predset_hash == 0` (and therefore `key == 0`) is the empty-slot
 * sentinel; healer_predset_hash() remaps the vanishingly rare FNV-1a
 * output of 0 to 1 so a real predset never collides with empty,
 * leaving the surrounding shm memset(0) as the only initialisation
 * the table needs.  pred_a and pred_b are stored sorted (pred_a <=
 * pred_b) so the (A, B) / (B, A) symmetry holds at insertion time;
 * they are narrowed to uint16_t -- syscall numbers fit (MAX_NR_SYSCALL
 * is 1024) and the caller already filters the EDGEPAIR_NO_PREV
 * (0xFFFF) sentinel before we ever reach a slot.
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
	struct healer_promoted promoted[HEALER_PROMOTED_PER_SLOT];
};

struct childdata;

/*
 * Observer hook fired on the new-edge branch of dispatch_step (and only
 * the new-edge branch -- the cost has to stay zero on the syscall hot
 * path).  Reads the child's last-2 completed syscall numbers out of
 * the per-child sequence buffer, sorts them, hashes the predset, and
 * either bumps the matching (predset, current_nr) entry or evicts the
 * lowest-weight entry to make room.  All updates are lockless: the
 * slot's identifier triple is CAS-claimed via the packed `key` field
 * and each promoted entry is mutated via a 64-bit CAS on its (nr,
 * weight) packed view, so concurrent observers never serialise on a
 * shared lock (see the table declaration in include/shm.h for the
 * memory-ordering argument).
 *
 * No-op until the child has executed at least two syscalls (the
 * sequence buffer needs both predecessor slots populated).
 */
void healer_observe_relation(struct childdata *child, unsigned int current_nr);

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
 * path; everyone else loses the CAS and returns.  Called from the same
 * observer-hook fire path that drives healer_observe_relation().
 */
void healer_maybe_snapshot(void);

/*
 * Pair-relation table -- single-predecessor companion to the
 * (predset -> nr) triple table above.  Indexed (pred -> succ); each
 * cell holds a single weight counter.  The canonical lives in
 * parent_healer.pair_table (parent-private, fed by the per-child
 * healer_ring observer events the drain applies under single-writer
 * discipline); the picker reads its values through the published
 * mirror page (healer_pair_published).  See include/healer_ring.h
 * for the retrofit topology.
 *
 * Bootstrapped from a static (producer -> consumer) prior derived from
 * existing ARG_FD_* / ret_objtype metadata via healer_load_static_seed(),
 * then refined at runtime by healer_pair_observe() firing on the
 * new-edge path alongside healer_observe_relation().  Pairs are
 * coarser-grained than the triples but converge MUCH faster from a
 * static prior than triples can.
 *
 * All three accessors silently no-op (or, for the read accessor,
 * return 0) when either syscall number is out of range, so callers
 * don't have to gate on MAX_NR_SYSCALL themselves.
 */
void healer_pair_seed(unsigned int pred, unsigned int succ, unsigned int weight);
void healer_pair_observe(unsigned int pred, unsigned int succ);
unsigned int healer_pair_get(unsigned int pred, unsigned int succ);

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

/*
 * Phase 1 stub for the coverage-plateau auto-response path.  Invoked
 * from kcov_plateau_check() on the rising-edge transition into PLATEAU
 * state, alongside the one-shot stats.log warning the detector emits.
 *
 * Phase 1 is detection-only: this stub just logs that a response would
 * fire here.  Future phases replace the body with the actual
 * intervention (bandit reseed, explorer pool bump, syscall-pool churn,
 * etc.) without further plumbing on the call-site side.  The function
 * lives outside healer.c because Phase 1 is intentionally a main-loop
 * / stats-side observability commit and does not modify HEALER
 * algorithm state.
 */
void healer_plateau_response(void);
