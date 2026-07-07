#pragma once

#include <stdbool.h>
#include <stddef.h>

/*
 * Per-(nr, do32) opaque-blob content corpus.
 *
 * Sibling of persist/minicorpus.c but scoped to blob CONTENT rather
 * than argument scalars.  minicorpus stores args[6] for a syscall
 * that produced novel coverage; those saved args include the pointer
 * to the ARG_BUF_SIZED buffer but not its bytes, so a minicorpus
 * replay lands the buffer pointer inside a fresh writable pool slot
 * that then gets blob_fill()'d with generate_rand_bytes() -- the
 * productive byte pattern that made the original save is discarded.
 *
 * This module closes that gap.  blob_fill() stashes the just-authored
 * buffer as a pending candidate keyed by (nr, do32); when the same
 * syscall completes with a productive-save signal, the pending stash
 * is promoted into a shared per-(nr, do32) slot table.  The next
 * ARG_BUF_SIZED call for the same key can pull the productive base
 * back out and lay HAVOC/CMPDICT on top instead of on top of fresh
 * random noise.
 *
 * The table is a small fixed-capacity flat array (BLOB_CORPUS_SLOTS
 * entries).  Lookup and eviction are bounded linear scans; there are
 * no per-syscall rings, no persistence, no growth.  A hit contract:
 * copy min(cap, entry_len) bytes into the caller's buffer -- callers
 * always pass a fresh writable buffer, so a partial fill overlaid with
 * HAVOC/CMPDICT is still a strict improvement over the all-random
 * baseline.
 *
 * OFF-mode reproducibility: nothing on this path runs when
 * blob_mutator_mode == BLOB_MUTATOR_OFF (blob_fill short-circuits
 * before stash/lookup fire), so the OFF arm remains byte-identical.
 */

/* Maximum bytes stored per slot.  Sized to cover the common
 * page_size / page_size+1 ARG_BUF_SIZED buckets without pinning the
 * long-tail 64 KiB blobs into the shared table -- a longer authored
 * buffer is truncated to this cap on stash, and a shorter draw simply
 * copies fewer bytes on retrieval. */
#define BLOB_CORPUS_MAX_LEN     4096u

/* Total slots in the flat table.  Kept small enough that a linear
 * scan across every slot is essentially free even at high fuzzing
 * rates; the per-(nr, do32) miss frequency the shadow ratio surfaces
 * is the trigger for revisiting this cap. */
#define BLOB_CORPUS_SLOTS       64u

/* Maximum pending-stash entries queued per syscall dispatch.  A
 * single syscall can carry more than one ARG_BUF_SIZED slot (e.g.
 * two-buffer copy_from_user pairs); six is the trinity num_args cap
 * so no pending stash from one dispatch can ever overflow. */
#define BLOB_CORPUS_PENDING_MAX 6u

/* Allocate the shared blob-corpus table.  Mirrors minicorpus_init()
 * -- called once from init_shm_publish_and_subsystems() before any
 * child forks.  Idempotent; safe to call before or after
 * minicorpus_init(). */
void blob_corpus_init(void);

/* Try to seed @buf with a productive blob base for (nr, do32).
 *
 * Returns true iff a stored entry was found; on hit, up to @len bytes
 * of the entry are copied into @buf (the tail is left untouched --
 * the caller has just handed us a writable pool slot whose residue
 * gets overlaid by HAVOC/CMPDICT anyway).  Bounded work: a single
 * linear scan of at most BLOB_CORPUS_SLOTS entries plus one memcpy
 * capped at BLOB_CORPUS_MAX_LEN.
 *
 * Safe to call from any context; returns false immediately when
 * the table is not yet initialised. */
bool blob_corpus_try_get_base(unsigned int nr, bool do32,
			      unsigned char *buf, size_t len);

/* Stash the just-authored buffer as a pending candidate for the next
 * minicorpus_save promotion.  Truncates to BLOB_CORPUS_MAX_LEN.  A
 * repeat stash for the same (nr, do32) key within a single pending
 * window overwrites; a stash beyond BLOB_CORPUS_PENDING_MAX is
 * dropped silently.
 *
 * Process-local.  No lock, no shared write.  Cleared per-dispatch
 * from generate_syscall_args() via blob_corpus_clear_pending(). */
void blob_corpus_stash_pending(unsigned int nr, bool do32,
			       const unsigned char *buf, size_t len);

/* Promote any pending stash entries into the shared table.  Called
 * from minicorpus_save_with_reason() on the productive-save
 * admission path (post argtype-replayability filter, post ring
 * insert) so promoted entries carry the same productivity provenance
 * as their args[6] siblings.  Also clears the pending stash after
 * copying so a subsequent save on the same dispatch cannot re-promote
 * the same bytes. */
void blob_corpus_promote_pending(void);

/* Drop the pending stash without promotion.  Called at the top of
 * generate_syscall_args() so an unpromoted pending from a previous
 * dispatch (no novelty signal fired) cannot leak into a fresh call. */
void blob_corpus_clear_pending(void);

/* Init-time invariant asserts.  Mirrors blob_mutator_self_check();
 * called from init_shm_publish_and_subsystems() so a broken build
 * cannot ship. */
void blob_corpus_self_check(void);
