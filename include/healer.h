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
 * hash output.  16384 slots * ~80 bytes per slot ~= 1.25 MiB of shm,
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
 * empty slot, the observation is dropped and shm->stats.healer_table_full
 * is bumped so the operator can spot a saturated table.  16 slots is
 * a reasonable compromise: with 16K slots and a 50%-full table the
 * expected probe length is ~2, so 16 leaves ample headroom for the
 * worst-case high-load tail.
 */
#define HEALER_PROBE_LIMIT       16

struct healer_promoted {
	unsigned int nr;
	unsigned int weight;	/* edge-discovery count attributed to this
				 * (predset, nr) tuple. */
};

/*
 * One relation-table slot.  `predset_hash == 0` is the empty-slot
 * sentinel (we remap the FNV-1a hash 0 to 1 explicitly so a real
 * predset never collides with empty).  pred_a and pred_b are stored
 * sorted (pred_a <= pred_b) so the (A, B) / (B, A) symmetry holds at
 * insertion time and there is no need to re-sort on lookup.
 */
struct healer_relation {
	unsigned int predset_hash;
	unsigned int pred_a;
	unsigned int pred_b;
	struct healer_promoted promoted[HEALER_PROMOTED_PER_SLOT];
	unsigned int promoted_count;
};

struct childdata;

/*
 * Observer hook fired on the new-edge branch of dispatch_step (and only
 * the new-edge branch -- the cost has to stay zero on the syscall hot
 * path).  Reads the child's last-2 completed syscall numbers out of
 * the per-child sequence buffer, sorts them, hashes the predset, and
 * either bumps the matching (predset, current_nr) entry or evicts the
 * lowest-weight entry to make room.  All updates happen under the
 * single coarse shm->healer_relations_lock (see the lock declaration
 * in include/shm.h for the contention argument).
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
