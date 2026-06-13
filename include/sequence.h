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
 * array size used in the chain corpus: each saved chain entry is stored
 * inline in a fixed-size slot of the chain_corpus_ring (see below), so
 * keeping the cap at 4 bounds the per-slot footprint and the total shm
 * cost of the ring.
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
 * The chain entries are stored inline in fixed-size slots of the ring
 * itself (struct chain_corpus_ring::slots[], see below).  The whole
 * ring -- header plus the inline slot array -- lives in a single
 * alloc_shared region so all forked children share one source of truth,
 * and the working set stays bounded as the ring overwrites old entries.
 *
 * The corpus is intentionally a separate structure from minicorpus_shared:
 * minicorpus is per-syscall-nr arg snapshots, this is per-chain-shape
 * syscall sequences.  Mixing them would conflate two different replay
 * policies under the same lock and slot accounting.
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
 * 256 inline chain_entry slots size the whole ring at ~74 KiB of shared
 * memory (see the sizing note on struct chain_corpus_ring::slots[]).
 * Larger than minicorpus's per-syscall ring count of 32 because the
 * chain corpus is a single global pool rather than one ring per syscall
 * — replay diversity comes from ring depth, not from per-syscall
 * partitioning.
 */
#define CHAIN_CORPUS_RING_SIZE 256

struct chain_corpus_ring {
	lock_t lock;
	unsigned int head;			/* next write slot mod CHAIN_CORPUS_RING_SIZE */
	unsigned int count;			/* entries stored, max CHAIN_CORPUS_RING_SIZE */
	unsigned long save_count;		/* chains saved on new-coverage (atomic) */
	unsigned long replay_count;		/* chains dispatched as replays (atomic) */
	/*
	 * Step-granular replay attribution counter.  replay_count above
	 * tracks chains; replay_steps_dispatched tracks individual replayed
	 * syscall steps that actually reached dispatch_step.  Replayed steps
	 * bypass set_syscall_nr() so they do not stamp child->strategy_at_pick
	 * and the post-syscall bandit-attribution sites deliberately skip
	 * them — this counter lets operators see how much of the workload
	 * has gone through that no-attribution path.
	 */
	unsigned long replay_steps_dispatched;	/* per-step replays dispatched (atomic) */
	/*
	 * Inline storage: a flat array of fixed-size entries living in this
	 * shm region directly, costing ~74 KiB total (256 * 296 B).  Holding
	 * the entries inline rather than behind a pointer table keeps the
	 * obj heap out of the chain corpus entirely, so the obj heap can
	 * stay mprotect'd RO post-init even though chain_corpus_save() runs
	 * in child context.
	 */
	struct chain_entry slots[CHAIN_CORPUS_RING_SIZE];
};

extern struct chain_corpus_ring *chain_corpus_shm;

void chain_corpus_init(void);
void chain_corpus_save(const struct chain_step *steps, unsigned int len);

/*
 * Snapshot a random saved chain into @out.  Returns true on success
 * (out->len populated, out->steps[] copied), false if the corpus is
 * empty.  The snapshot is intentionally lockless -- see the long
 * comment in chain_corpus_pick() (sequence.c) for the race tolerance
 * argument.  Callers MUST validate out->len before indexing
 * out->steps[]: a torn lockless read or wild write into the shared
 * slot can leave len outside [1, MAX_SEQ_LEN].  run_sequence_chain()
 * does that validation and falls back to a fresh chain on failure.
 */
bool chain_corpus_pick(struct chain_entry *out);
