/*
 * Sequence-aware fuzzing — chain executor and chain corpus.
 *
 * Phase 1 dispatches a short chain of random syscalls per fuzzer iteration
 * and threads each call's return value into the next call's args with a
 * tunable probability.  Phase 2 (this file) adds a save-side corpus: when
 * a chain produces new KCOV edges, the chain (per-step nr/do32bit/args/
 * retval) is captured into a global ring of saved chains so a future
 * iteration can replay it with mutation.  The replay path is wired in a
 * follow-up change; this commit lands the storage and the save trigger
 * so saved chains start accumulating without behaviour change to the
 * dispatch path.  Phase 3 (deferred) will add resource-type dependency
 * tracking so chains can be generated with structural awareness of which
 * calls produce and consume which kinds of resource.
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
#include "trinity.h"
#include "utils.h"

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
 * Push a fresh chain into the ring, evicting the oldest slot if the
 * ring is full.  The eviction free is performed AFTER the lock is
 * released because once we have replaced ring->slots[slot] under the
 * lock, no concurrent reader can land on the evicted pointer — they
 * either saw the old pointer before our store and are working with
 * a stable copy, or they see the new pointer.  Holding the lock
 * across free_shared_obj would needlessly extend the critical section.
 *
 * Errno-only allocation failures (heap exhausted, etc.) are silently
 * dropped: missing one save event is a measurement loss, not a
 * correctness issue, and the next productive chain will save normally.
 */
void chain_corpus_save(const struct chain_step *steps, unsigned int len)
{
	struct chain_corpus_ring *ring = chain_corpus_shm;
	struct chain_entry *ent;
	struct chain_entry *evicted = NULL;
	unsigned int slot;

	if (ring == NULL || len == 0 || len > MAX_SEQ_LEN)
		return;

	ent = alloc_shared_obj(sizeof(struct chain_entry));
	if (ent == NULL)
		return;

	ent->len = len;
	memcpy(ent->steps, steps, len * sizeof(struct chain_step));

	lock(&ring->lock);

	slot = ring->head % CHAIN_CORPUS_RING_SIZE;
	evicted = ring->slots[slot];
	ring->slots[slot] = ent;
	ring->head++;
	if (ring->count < CHAIN_CORPUS_RING_SIZE)
		ring->count++;

	unlock(&ring->lock);

	if (evicted != NULL)
		free_shared_obj(evicted, sizeof(struct chain_entry));

	__atomic_fetch_add(&ring->save_count, 1UL, __ATOMIC_RELAXED);
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
	unsigned int steps_recorded = 0;
	unsigned int len, i;
	bool have_substitute = false;
	unsigned long substitute_retval = 0;
	bool chain_found_new = false;

	len = pick_chain_length();

	for (i = 0; i < len; i++) {
		bool step_ret;
		bool step_found_new = false;
		unsigned long rv;

		step_ret = random_syscall_step(child, have_substitute,
					       substitute_retval,
					       &step_found_new);
		if (step_ret == FAIL)
			return FAIL;

		/* Snapshot the dispatched call into the chain buffer.  Done
		 * after random_syscall_step returns so the args reflect any
		 * Phase 1 retval substitution and the retval is the kernel's
		 * actual return.  cmp-mode steps have step_found_new == false
		 * (kcov_collect was skipped) — they still get recorded in
		 * the chain so replays preserve chain shape, but they don't
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
	 * keeping for replay.  Length-1 chains aren't saved (trivially
	 * subsumed by the per-syscall minicorpus); the chain length floor
	 * of 2 from pick_chain_length() makes that condition redundant in
	 * practice but the explicit check keeps the contract obvious. */
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
