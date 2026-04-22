/*
 * Sequence-aware fuzzing — chain executor and chain corpus.
 *
 * Phase 1 dispatches a short chain of random syscalls per fuzzer iteration
 * and threads each call's return value into the next call's args with a
 * tunable probability.  Phase 2 (this file) mines productive chains into a
 * global ring of saved chains, and replays them on a fraction of future
 * iterations with the per-arg mutator chain that the per-call mini-corpus
 * already runs (cross-arg splice + weighted-stack mutate + fd safety).
 * Phase 3 (deferred) will add resource-type dependency tracking so chains
 * are generated with structural awareness of which calls produce and
 * consume which kinds of resource.
 *
 * Chain length is drawn from a geometric distribution biased toward 2:
 * P(2)=50%, P(3)=30%, P(4)=20%.  The bias toward 2 is deliberate —
 * most setup-then-use kernel paths fit in two calls (open then ioctl,
 * socket then sendmsg), and shorter chains preserve fuzzer throughput
 * while still exercising the longer-tail patterns at lower frequency.
 *
 * Substitution-vs-failure: if a step's retval is negative (errno-style
 * failure) the next step is dispatched without a substitute, since
 * passing -EBADF as an fd to the following call wastes the slot.  The
 * chain itself continues — a single mid-chain failure does not abort
 * the remaining steps.
 */

#include <stdlib.h>
#include <string.h>

#include "child.h"
#include "kcov.h"
#include "minicorpus.h"
#include "random.h"
#include "sequence.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/*
 * Probability (as 1/N) that an iteration replays a saved chain instead
 * of generating a fresh one.
 *
 * 4 == 25%.  Same starting point as minicorpus_replay's per-call replay
 * rate, picked so the two replay paths sit at the same baseline and
 * any divergence in coverage productivity between per-call and per-
 * chain replay is attributable to the structural difference rather
 * than to a sampling rate gap.  Lower than 50/50 because fresh
 * generation is still where new chain shapes are discovered — a
 * replay-dominated mix would saturate on the seed distribution that
 * Phase 1's random chain length and arg generation produce.  The
 * gating is in run_sequence_chain so the replay rate can be tuned
 * here without touching the dispatch code.
 */
#define CHAIN_REPLAY_RATIO 4

struct chain_corpus_ring *chain_corpus_shm = NULL;

void chain_corpus_init(void)
{
	/* No coverage signal means no save trigger; skip the allocation
	 * and let chain_corpus_save / dump_stats fall through their NULL
	 * guards.  Mirrors the same kcov_shm gate that minicorpus_init
	 * uses for the same reason. */
	if (kcov_shm == NULL)
		return;

	chain_corpus_shm = alloc_shared(sizeof(struct chain_corpus_ring));
	memset(chain_corpus_shm, 0, sizeof(struct chain_corpus_ring));
	output(0, "Sequence chain corpus allocated (%u slots, %lu B per entry)\n",
		CHAIN_CORPUS_RING_SIZE,
		(unsigned long) sizeof(struct chain_entry));
}

/*
 * Replay-safety filter for chain corpus entries.
 *
 * Returns true if every step in @steps could be replayed without
 * feeding stale heap pointers, stale pids, or sanitise-stashed
 * pointers to the kernel.  Same exclusions as minicorpus_save (which
 * treats these arg types as poison) plus the entry->sanitise gate
 * that random-syscall.c applies before it calls minicorpus_save.
 *
 * The check happens at save time so the corpus only ever contains
 * chains that are themselves replay-safe.  Saving an unsafe chain and
 * filtering at replay time would let unsafe entries displace safe ones
 * out of the ring as it wraps, and would shrink the effective corpus
 * size whenever the unsafe fraction was non-trivial.
 */
static bool chain_is_replay_safe(const struct chain_step *steps,
				 unsigned int len)
{
	unsigned int i, j;

	for (i = 0; i < len; i++) {
		struct syscallentry *entry = get_syscall_entry(steps[i].nr,
							       steps[i].do32bit);

		if (entry == NULL || entry->sanitise != NULL)
			return false;

		for (j = 0; j < entry->num_args && j < 6; j++) {
			switch (entry->argtype[j]) {
			case ARG_IOVEC:
			case ARG_PATHNAME:
			case ARG_SOCKADDR:
			case ARG_MMAP:
			case ARG_PID:
				return false;
			default:
				break;
			}
		}
	}
	return true;
}

/*
 * Push a fresh chain into the ring, overwriting the oldest slot in place
 * when the ring is full.  Slots are inline structs in shm (no separate
 * allocation), so the write is a memcpy under the ring lock and there is
 * no eviction free path to defer.
 */
void chain_corpus_save(const struct chain_step *steps, unsigned int len)
{
	struct chain_corpus_ring *ring = chain_corpus_shm;
	struct chain_entry *ent;
	unsigned int slot;

	if (ring == NULL || len == 0 || len > MAX_SEQ_LEN)
		return;

	if (!chain_is_replay_safe(steps, len))
		return;

	lock(&ring->lock);

	slot = ring->head % CHAIN_CORPUS_RING_SIZE;
	ent = &ring->slots[slot];
	ent->len = len;
	memcpy(ent->steps, steps, len * sizeof(struct chain_step));
	ring->head++;
	if (ring->count < CHAIN_CORPUS_RING_SIZE)
		ring->count++;

	unlock(&ring->lock);

	__atomic_fetch_add(&ring->save_count, 1UL, __ATOMIC_RELAXED);
}

bool chain_corpus_pick(struct chain_entry *out)
{
	struct chain_corpus_ring *ring = chain_corpus_shm;
	unsigned int slot;

	if (ring == NULL || out == NULL)
		return false;

	/* Lock-protected snapshot.  Holding the lock for the memcpy keeps
	 * the snapshot consistent against a concurrent in-place save
	 * overwriting the slot we are reading from. */
	lock(&ring->lock);

	if (ring->count == 0) {
		unlock(&ring->lock);
		return false;
	}

	/* Pick uniformly across the live entries.  The newest entry is
	 * at (head - 1), the oldest at (head - count); both wrap mod
	 * CHAIN_CORPUS_RING_SIZE. */
	slot = (ring->head - ring->count + (rand() % ring->count)) %
	       CHAIN_CORPUS_RING_SIZE;
	*out = ring->slots[slot];

	unlock(&ring->lock);
	return true;
}

#if ENABLE_SEQUENCE_CHAIN

static unsigned int pick_chain_length(void)
{
	unsigned int r = rand() % 10;

	if (r < 5)
		return 2;
	if (r < 8)
		return 3;
	return 4;
}

bool run_sequence_chain(struct childdata *child)
{
	struct syscallrecord *rec = &child->syscall;
	struct chain_step steps[MAX_SEQ_LEN];
	struct chain_entry replay;
	const struct chain_step *replay_template = NULL;
	unsigned int steps_recorded = 0;
	unsigned int len, i;
	bool have_substitute = false;
	unsigned long substitute_retval = 0;
	bool chain_found_new = false;
	bool replaying = false;

	/* With CHAIN_REPLAY_RATIO probability, try to replay a saved chain
	 * rather than generate a fresh one.  Falls back to fresh if the
	 * corpus is empty (warm-start) or if the picked chain is rejected
	 * mid-replay by replay_syscall_step's safety checks (deactivated
	 * syscall, sanitise that wasn't there at save time, etc.). */
	if (chain_corpus_shm != NULL && ONE_IN(CHAIN_REPLAY_RATIO) &&
	    chain_corpus_pick(&replay)) {
		replaying = true;
		replay_template = replay.steps;
		len = replay.len;
		__atomic_fetch_add(&chain_corpus_shm->replay_count, 1UL,
				   __ATOMIC_RELAXED);
	} else {
		len = pick_chain_length();
	}

	for (i = 0; i < len; i++) {
		bool step_ret;
		bool step_found_new = false;
		unsigned long rv;

		if (replaying) {
			step_ret = replay_syscall_step(child,
						       &replay_template[i],
						       have_substitute,
						       substitute_retval,
						       &step_found_new);
			if (step_ret == FAIL) {
				/* Replay safety check failed (saved syscall
				 * has been deactivated or otherwise become
				 * unreplayable since save).  Drop into fresh
				 * generation for the rest of the chain so the
				 * iteration still does useful work. */
				replaying = false;
				step_ret = random_syscall_step(child,
							       have_substitute,
							       substitute_retval,
							       &step_found_new);
			}
		} else {
			step_ret = random_syscall_step(child,
						       have_substitute,
						       substitute_retval,
						       &step_found_new);
		}

		if (step_ret == FAIL)
			return FAIL;

		/* Snapshot the dispatched call into the chain buffer.  Done
		 * after dispatch returns so the args reflect any Phase 1
		 * retval substitution and the retval is the kernel's actual
		 * return.  cmp-mode steps have step_found_new == false
		 * (kcov_collect was skipped) — they still get recorded in
		 * the chain so saves preserve chain shape, but they don't
		 * by themselves trigger a chain save. */
		if (steps_recorded < MAX_SEQ_LEN) {
			struct chain_step *cs = &steps[steps_recorded++];

			cs->nr = rec->nr;
			cs->do32bit = rec->do32bit;
			cs->args[0] = rec->a1;
			cs->args[1] = rec->a2;
			cs->args[2] = rec->a3;
			cs->args[3] = rec->a4;
			cs->args[4] = rec->a5;
			cs->args[5] = rec->a6;
			cs->retval = rec->retval;
		}

		if (step_found_new)
			chain_found_new = true;

		/* Decide whether the next step may receive a substitute.
		 * Errno-style returns (-1..-4095 region, all negative when
		 * read as long) are dropped because they are unlikely to
		 * be useful as downstream arg values.  Zero is allowed
		 * through — RET_ZERO_SUCCESS calls return 0 on success
		 * and a NULL substituted into a pointer slot is a useful
		 * boundary case to exercise. */
		rv = child->syscall.retval;
		if ((long)rv < 0) {
			have_substitute = false;
			substitute_retval = 0;
		} else {
			have_substitute = true;
			substitute_retval = rv;
		}
	}

	/* Save chains that produced new coverage in any step.  The same
	 * found_new signal that drives the per-call minicorpus save and the
	 * weighted_pick_case attribution gates this — chains the rest of
	 * the fuzzer already considers interesting are the chains worth
	 * keeping for replay.  Saves apply equally to fresh chains and to
	 * mutated replays of saved chains: a replay that finds new edges
	 * proves the mutated form was structurally distinct from its
	 * parent and is worth retaining as a corpus entry in its own
	 * right.  Length-1 chains aren't saved (trivially subsumed by
	 * the per-syscall minicorpus); the chain length floor of 2 from
	 * pick_chain_length() makes that condition redundant in practice
	 * but the explicit check keeps the contract obvious. */
	if (chain_found_new && steps_recorded >= 2)
		chain_corpus_save(steps, steps_recorded);

	if (minicorpus_shm != NULL)
		__atomic_fetch_add(&minicorpus_shm->chain_iter_count, 1,
				   __ATOMIC_RELAXED);

	return true;
}

#else /* !ENABLE_SEQUENCE_CHAIN */

bool run_sequence_chain(struct childdata *child)
{
	return random_syscall(child);
}

#endif
