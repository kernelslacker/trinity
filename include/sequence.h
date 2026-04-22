#pragma once

#include "child.h"
#include "locks.h"

/*
 * Sequence-aware fuzzing.
 *
 * Phase 1 dispatches a 2-4 syscall chain per fuzzer iteration instead of
 * a single call.  Between consecutive calls, the previous call's return
 * value may be substituted into one randomly-chosen arg slot of the next
 * call.  Phase 2 mines productive chains into a corpus so that future
 * iterations can replay them with mutation, closing the AFL-style queue
 * feedback loop at chain granularity rather than the per-call granularity
 * that the existing minicorpus already covers.  Phase 3 (deferred) will
 * add resource-type dependency tracking so that chains can be generated
 * with structural awareness of which calls produce and consume which
 * kinds of resource.
 *
 * Set ENABLE_SEQUENCE_CHAIN to 0 to fall back to the legacy one-call-per
 * iteration dispatch for A/B coverage comparison.
 */
#define ENABLE_SEQUENCE_CHAIN 1

/*
 * Hard cap on chain length.  pick_chain_length() draws from {2,3,4} via
 * a geometric distribution biased toward 2.  The cap is also the step-
 * array size used in the chain corpus: keeping it at 4 keeps each saved
 * chain entry small enough to land inside a single freelist bucket on
 * the shared obj heap, so save / evict cycles recycle slots cleanly
 * rather than bumping the heap watermark forever.
 */
#define MAX_SEQ_LEN 4

bool run_sequence_chain(struct childdata *child);

/*
 * Sequence chain corpus (Phase 2).
 *
 * When a freshly-randomised chain produces new KCOV edges in any of its
 * steps, the chain (per-step nr/do32bit/args/retval) is captured into a
 * global shared-memory ring of saved chains.  Subsequent iterations may
 * replay a saved chain with per-arg mutation instead of generating a
 * fresh one.  Save-on-new-coverage is the right trigger because it is
 * the same signal the per-call minicorpus already uses to decide which
 * arg snapshots are worth retaining; piggybacking on it means the chain
 * corpus inherits the same "interesting input" definition that the rest
 * of the fuzzer is already optimising against.
 *
 * The chain entries themselves are dynamically allocated through
 * alloc_shared_obj.  Each entry is fixed-size (264 B), so eviction
 * recycles into the freelist's 512-byte bucket and the working set
 * stays bounded as the ring overwrites old entries.  The ring header
 * (head / count / lock plus the slot-pointer array) lives in a single
 * alloc_shared region so all forked children share one source of truth.
 *
 * The corpus is intentionally a separate structure from minicorpus_shared
 * even though it shares the alloc_shared_obj backend: minicorpus is
 * per-syscall-nr arg snapshots, this is per-chain-shape syscall sequences.
 * Mixing them would conflate two different replay policies under the same
 * lock and slot accounting.
 */
struct chain_step {
	unsigned int nr;
	bool do32bit;
	unsigned long args[6];
	unsigned long retval;
};

struct chain_entry {
	unsigned int len;			/* number of valid steps (1..MAX_SEQ_LEN) */
	struct chain_step steps[MAX_SEQ_LEN];
};

/*
 * Ring depth for saved chains.
 *
 * 256 slots * ~512 B per chain_entry through the freelist bucket caps
 * the in-flight chain corpus at ~128 KiB, well clear of the 4 MiB
 * shared obj heap.  Larger than minicorpus's per-syscall ring count of
 * 32 because the chain corpus is a single global pool rather than one
 * ring per syscall — replay diversity comes from ring depth, not from
 * per-syscall partitioning.
 */
#define CHAIN_CORPUS_RING_SIZE 256

struct chain_corpus_ring {
	lock_t lock;
	unsigned int head;			/* next write slot mod CHAIN_CORPUS_RING_SIZE */
	unsigned int count;			/* entries stored, max CHAIN_CORPUS_RING_SIZE */
	unsigned long save_count;		/* chains saved on new-coverage (atomic) */
	struct chain_entry *slots[CHAIN_CORPUS_RING_SIZE];
};

extern struct chain_corpus_ring *chain_corpus_shm;

void chain_corpus_init(void);
void chain_corpus_save(const struct chain_step *steps, unsigned int len);
