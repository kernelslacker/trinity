/*
 * Mini-corpus mutate accept-reject accounting.
 *
 * Holds the per-process attribution stashes that the mutator engine
 * bumps as it works and drains them into fleet-wide trials/wins on the
 * post-syscall commit.  Split out of minicorpus-mutate.c so the
 * accounting rules (baseline gate, source-age histogram, per-tag
 * struct-field credit, replay/splice/xprop win counters) live in one
 * place, separate from the mutator picker and the splice-and-mutate
 * driver that populate the stash.
 */

#include "child.h"
#include "minicorpus.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"

#include "minicorpus-internal.h"

/*
 * Per-process attribution stash for the weighted mutator scheduler.
 *
 * mutate_arg() bumps mut_attrib[op] every time it picks case `op`.  After
 * the syscall completes, the post-coverage path drains the stash via
 * minicorpus_mut_attrib_commit(), folding it into shm-wide trials/wins.
 *
 * Process-local — children fork before any mutate_arg call, so each child
 * has its own copy.  No locking needed: a child runs single-threaded.
 */
unsigned int mut_attrib[MUT_NUM_OPS];

/*
 * Parallel structured-firing stash.  Bumped from inside mutate_arg
 * whenever the structure-aware branch ran (ARG_LIST / ARG_OP /
 * ARG_RANGE with usable arg_param metadata).  Drained by
 * minicorpus_mut_attrib_commit into shm->mut_structured_trials /
 * mut_structured_wins so per-op structured productivity can be
 * compared against the existing aggregate mut_trials / mut_wins.
 * Same per-process / fork-then-single-threaded guarantee as
 * mut_attrib above.
 */
unsigned int mut_structured_attrib[MUT_NUM_OPS];

/*
 * Process-local replay and splice attribution flags.
 *
 * Set by minicorpus_replay() when the respective event occurs; consumed
 * and cleared by minicorpus_mut_attrib_commit() to attribute wins without
 * needing a second pass over the call path.  Per-process — same
 * fork/single-threaded guarantee as mut_attrib[].
 */
bool this_replay_ran;
bool this_replay_spliced;
bool this_replay_xprop;

/*
 * Process-local post-replay perturbation attribution flag.  Set by
 * minicorpus_replay_perturbation_mark() when the caller has actually
 * landed a light FT_FLAGS/FT_RANGE neighbour mutation on a cataloged
 * struct-ptr arg; consumed and cleared by minicorpus_mut_attrib_commit
 * to bump replay_perturbed_wins on found_new.  Same fork/single-
 * threaded guarantee as the other this_replay_* stashes above.
 */
static bool this_replay_perturbed;

/*
 * Process-local per-syscall-replay source pointer.
 *
 * minicorpus_replay() sets these to the (nr, slot) of the corpus entry it
 * picked, so commit() can read and bump the entry's novel_replay_hits
 * baseline counter and gate mutator-win credit on that baseline.
 * Chain-replay (replay_syscall_step) does NOT have a source corpus entry
 * and leaves the flag false; commit() then skips per-op trials/wins
 * updates for chain-replay events so the bandit signal in mut_trials[]/
 * mut_wins[] reflects only the per-syscall-replay path where a baseline
 * can be established.
 *
 * Race tolerance: between minicorpus_replay's slot pick and commit() the
 * ring may rotate and evict the entry, so source_slot can point at a
 * different entry by the time we read its novel_replay_hits.  Crediting
 * a sibling entry's baseline is benign noise -- same shape as the
 * existing replay torn-read tolerance.  Cleared unconditionally in
 * commit() so a fall-through path can't leak source-tracked state into
 * a subsequent chain-replay commit.
 */
bool this_replay_source_tracked;
unsigned int this_replay_source_nr;
unsigned int this_replay_source_slot;
/* Source-entry age (distance-from-head, in slots) at
 * replay-pick time.  Stashed at minicorpus_replay() pick and consumed
 * by minicorpus_mut_attrib_commit() to bin replay_wins_by_age.  Same
 * per-process / fork-then-single-threaded guarantee as the other
 * this_replay_* stashes above; unsigned so an untracked-source
 * commit just sees 0 without touching the histogram (gated on
 * this_replay_source_tracked). */
unsigned int this_replay_source_age;

/*
 * Process-local CMP-source attribution flag.
 *
 * Set by minicorpus_mut_attrib_set_cmp_source() when the post-syscall
 * coverage signal that's about to drive commit() is CMP-bloom novelty
 * rather than PC-edge novelty.  Consumed and cleared by
 * minicorpus_mut_attrib_commit() -- if (found_new && this_attrib_cmp_source)
 * we bump the dedicated mut_attrib_cmp_wins scalar so stats can
 * separate the two sources without changing mut_wins[]/mut_trials[]
 * (which the weighted scheduler reads).  Same fork/single-threaded
 * guarantee as this_replay_ran above.
 */
static bool this_attrib_cmp_source;

/*
 * Process-local C.2b post-fill struct-field attribution stash.  Set by
 * minicorpus_struct_field_attrib() when struct_field_mutate_one applies
 * a per-tag primitive; consumed and cleared by
 * minicorpus_mut_attrib_commit().  At most one tag per call by
 * construction -- the gated entry point mutates exactly one field per
 * invocation -- so a simple (set, tag) pair captures everything the
 * commit needs.  Same per-process / fork-then-single-threaded guarantee
 * as the rest of the attribution stash.
 */
static enum field_tag this_struct_field_tag;
static bool this_struct_field_set;

void minicorpus_mut_attrib_set_cmp_source(void)
{
	this_attrib_cmp_source = true;
}

void minicorpus_replay_perturbation_mark(void)
{
	this_replay_perturbed = true;
}

void minicorpus_struct_field_attrib(enum field_tag tag)
{
	this_struct_field_tag = tag;
	this_struct_field_set = true;
}

static void minicorpus_mut_attrib_perop_accounting(bool found_new)
{
	unsigned int i;

	/* Per-op mutator accounting is gated on having a tracked source
	 * corpus entry (i.e., the call came from minicorpus_replay, not
	 * chain-replay).  Chain-replay shares the same mutator engine but
	 * has no per-entry baseline to subtract intrinsic novelty against,
	 * so feeding its events into mut_trials[]/mut_wins[] would re-
	 * introduce the corpus-marginal-novelty signal that the per-entry
	 * baseline exists to filter out.  Clear the stash unconditionally
	 * so the next call starts clean regardless of whether we credited.
	 *
	 * Per-op granularity: bump trials/wins by ONE per call per op that
	 * participated (mut_attrib[op] > 0), not by the raw pick count.
	 * Crediting per pick would inflate each call's win signal by its
	 * stack depth, masking real op-quality differences under the
	 * common per-call novelty rate (the uniform ~0.07% pathology).
	 *
	 * Per-entry baseline gate: even on a tracked-source call,
	 * mut_wins[] is only bumped if the source entry has produced novel
	 * coverage in a previous replay (novel_replay_hits > 0).  The first
	 * productive replay of an entry establishes the baseline -- those
	 * edges are the entry's intrinsic value, not the mutator's -- and
	 * is counted as a trial but not a win.  Subsequent productive
	 * replays cross the baseline and are credited to the mutator.
	 */
	if (this_replay_source_tracked) {
		struct corpus_entry *src_entry = NULL;
		bool baseline_established = false;

		if (this_replay_source_nr < MAX_NR_SYSCALL &&
		    this_replay_source_slot < CORPUS_RING_SIZE) {
			src_entry = &minicorpus_shm->rings[this_replay_source_nr]
				    .entries[this_replay_source_slot];
			baseline_established =
				__atomic_load_n(&src_entry->novel_replay_hits,
						__ATOMIC_RELAXED) > 0;
		}

		for (i = 0; i < MUT_NUM_OPS; i++) {
			if (mut_attrib[i] != 0) {
				__atomic_fetch_add(&minicorpus_shm->mut_trials[i],
						   1UL, __ATOMIC_RELAXED);
				if (found_new && baseline_established)
					__atomic_fetch_add(&minicorpus_shm->mut_wins[i],
							   1UL, __ATOMIC_RELAXED);
				mut_attrib[i] = 0;
			}

			/* Structured-firing accounting lives on a parallel
			 * stash because a single call may pick op `i` more
			 * than once with only some of those picks landing on
			 * a structured-typed slot.  Bumped per-call (not
			 * per-pick) and gated by the same baseline rule as
			 * the unstructured pair so the two ratios stay
			 * apples-to-apples. */
			if (mut_structured_attrib[i] != 0) {
				__atomic_fetch_add(&minicorpus_shm->mut_structured_trials[i],
						   1UL, __ATOMIC_RELAXED);
				if (found_new && baseline_established)
					__atomic_fetch_add(&minicorpus_shm->mut_structured_wins[i],
							   1UL, __ATOMIC_RELAXED);
				mut_structured_attrib[i] = 0;
			}
		}

		/* Advance the source entry's baseline if this replay was
		 * productive.  Bump unconditionally on found_new -- baseline
		 * tracking is independent of whether wins were credited this
		 * call (the first productive replay bumps to 1 without
		 * crediting, unlocking subsequent calls).  Tolerates a slot
		 * eviction race: a sibling entry's baseline gets advanced
		 * instead, which is the same benign mis-attribution shape as
		 * the gate read above. */
		if (found_new && src_entry != NULL)
			__atomic_fetch_add(&src_entry->novel_replay_hits,
					   1U, __ATOMIC_RELAXED);

		/* Replay-wins-by-entry-age.  Same
		 * found_new gate the baseline advance above uses --
		 * "productive replay of a tracked source" — but
		 * unconditional on baseline_established because the
		 * histogram measures *coverage discovery* per age
		 * bucket regardless of whether the discovery is the
		 * entry's intrinsic novelty or a mutator credit.
		 * Bucket index = floor(log2(age)) + 1 with age==0
		 * landing in bucket 0; saturates at the last bucket
		 * so any age the ring can hold lands in a defined
		 * slot. */
		if (found_new) {
			unsigned int age = this_replay_source_age;
			unsigned int bucket;

			if (age == 0)
				bucket = 0;
			else {
				unsigned int lz = (unsigned int)__builtin_clz(age);
				unsigned int hi_bit = 31u - lz;

				bucket = hi_bit + 1u;
				if (bucket >= ARRAY_SIZE(minicorpus_shm->replay_wins_by_age))
					bucket = ARRAY_SIZE(minicorpus_shm->replay_wins_by_age) - 1u;
			}
			__atomic_fetch_add(
				&minicorpus_shm->replay_wins_by_age[bucket],
				1UL, __ATOMIC_RELAXED);
		}

		this_replay_source_tracked = false;
	} else {
		/* Untracked source (chain-replay or other non-minicorpus
		 * caller).  Clear both stashes without recording per-op
		 * events -- the bandit signal (and the structured-firing
		 * companion) stays exclusively per-syscall-replay. */
		for (i = 0; i < MUT_NUM_OPS; i++) {
			mut_attrib[i] = 0;
			mut_structured_attrib[i] = 0;
		}
	}

	if (this_replay_ran) {
		if (found_new)
			__atomic_fetch_add(&minicorpus_shm->replay_wins,
					   1UL, __ATOMIC_RELAXED);
		this_replay_ran = false;
	}

	if (this_replay_spliced) {
		if (found_new)
			__atomic_fetch_add(&minicorpus_shm->splice_wins,
					   1UL, __ATOMIC_RELAXED);
		this_replay_spliced = false;
	}

	if (this_replay_xprop) {
		if (found_new)
			__atomic_fetch_add(&minicorpus_shm->xprop_wins,
					   1UL, __ATOMIC_RELAXED);
		this_replay_xprop = false;
	}

	if (this_replay_perturbed) {
		if (found_new)
			__atomic_fetch_add(&minicorpus_shm->replay_perturbed_wins,
					   1UL, __ATOMIC_RELAXED);
		this_replay_perturbed = false;
	}
}

void minicorpus_mut_attrib_commit(bool found_new)
{
	unsigned int i;

	/* Clear the per-child replay-provenance flag unconditionally,
	 * regardless of whether the call had a tracked corpus source.  The
	 * flag is set inside minicorpus_replay() right after the snapshot
	 * picks an entry tagged rq_sourced, and consumed by
	 * frontier_record_new_edge() during the call's kcov pass which has
	 * already completed by the time we get here.  Clearing here keeps
	 * the next iteration's frontier_record_new_edge from mis-crediting
	 * its PC win to a stale source -- whether the next call is a
	 * non-replay (fresh args) or a replay of a non-rq-sourced entry. */
	{
		struct childdata *cc = this_child();

		if (cc != NULL) {
			cc->replay_rq_sourced = false;
			cc->replay_errno_sourced = false;
		}
	}

	if (minicorpus_shm == NULL) {
		/* Still clear the per-process tag so a future shm-armed
		 * commit() doesn't see stale state from before init. */
		this_attrib_cmp_source = false;
		this_replay_source_tracked = false;
		this_struct_field_set = false;
		this_replay_perturbed = false;
		for (i = 0; i < MUT_NUM_OPS; i++)
			mut_structured_attrib[i] = 0;
		return;
	}

	minicorpus_mut_attrib_perop_accounting(found_new);

	/* CMP-source wins counter.  Bumped at most once per commit so its
	 * units match "calls credited as CMP-source wins" not "per-arg
	 * mutator picks" -- the latter is already covered by mut_wins[]
	 * which the bandit-weighting math consumes unchanged.  Cleared
	 * unconditionally so a stale flag from a found_new=false call
	 * doesn't leak into the next call's attribution. */
	if (this_attrib_cmp_source) {
		if (found_new)
			__atomic_fetch_add(
				&minicorpus_shm->mut_attrib_cmp_wins,
				1UL, __ATOMIC_RELAXED);
		this_attrib_cmp_source = false;
	}

	/*
	 * Per-tag attribution for the C.2b post-fill struct-field mutator.
	 * Exactly one tag per call by construction (struct_field_mutate_one
	 * picks at most one field per invocation), so the stash is a simple
	 * (set, tag) pair.  Trials bump unconditionally on a set stash --
	 * the stash being set IS the "we did a mutation" signal -- and wins
	 * bump only on found_new.  Independent of the per-syscall-replay
	 * baseline gate used by the MUT_NUM_OPS counters above: post-fill
	 * mutation runs on fresh-fill calls, never on replay, so there is
	 * no per-entry baseline to subtract.  Out-of-range tag bytes are
	 * defensively rejected before the shm write so a future caller
	 * passing a typo'd tag can't corrupt a neighbouring counter slot.
	 */
	if (this_struct_field_set) {
		unsigned int tag = (unsigned int) this_struct_field_tag;

		if (tag < FT_NUM_TAGS) {
			__atomic_fetch_add(
				&minicorpus_shm->mut_struct_field_trials[tag],
				1UL, __ATOMIC_RELAXED);
			if (found_new)
				__atomic_fetch_add(
					&minicorpus_shm->mut_struct_field_wins[tag],
					1UL, __ATOMIC_RELAXED);
		}
		this_struct_field_set = false;
	}
}
