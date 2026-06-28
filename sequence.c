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
 * Chain length is drawn from pick_chain_length()'s discrete
 * distribution centred on 3: P(2)=30%, P(3)=40%, P(4)=30%.  Two-call
 * chains remain a common setup-then-use shape (open then ioctl,
 * socket then sendmsg) but the rebalanced weights -- moved here
 * from an earlier 50/30/20 bias toward 2 -- give length-3
 * setup-then-use-then-tear sequences the largest share, which is
 * where the chain corpus saw most of its productive replays.  Four
 * remains a backstop for the longer-tail patterns at the same 30%
 * rate; lengths beyond 4 are out of scope for this phase.
 *
 * Substitution-vs-failure: if a step's retval is negative (errno-style
 * failure) the next step is dispatched without a substitute, since
 * passing -EBADF as an fd to the following call wastes the slot.  The
 * chain itself continues — a single mid-chain failure does not abort
 * the remaining steps.
 */

#include <stdint.h>
#include <string.h>

#include "child.h"
#include "kcov.h"
#include "minicorpus.h"
#include "random.h"
#include "rnd.h"
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

/*
 * Probability divisor (1/N) applied to replay picks whose source chain
 * was admitted under a non-PC reason (TRANSITION / CMP).  The non-PC save
 * reasons exist to grow the corpus on the warm-PC plateau where the PC-
 * only gate produces ~zero saves; until per-reason replay productivity
 * data is in (chain_replay_win_by_reason[] vs chain_save_by_reason[]) we
 * deliberately pull non-PC replays at half the PC-saved rate.  Anchored
 * to PC-saved replays at the full CHAIN_REPLAY_RATIO so the comparison
 * stays controlled: any divergence in coverage productivity between PC-
 * saved and non-PC-saved chain replay is attributable to the source
 * signal rather than to a sampling rate gap.
 */
#define CHAIN_REPLAY_NONPC_DOWNSAMPLE 2

struct chain_corpus_ring *chain_corpus_shm = NULL;

void chain_corpus_init(void)
{
	/* No coverage signal means no save trigger; skip the allocation
	 * and let chain_corpus_save / dump_stats fall through their NULL
	 * guards.  Mirrors the same kcov_shm gate that minicorpus_init
	 * uses for the same reason. */
	if (kcov_shm == NULL)
		return;

	/*
	 * Wild-write risk: a child syscall buffer pointer aliasing into a
	 * slot could corrupt a stored chain (next replay dispatches garbage
	 * syscalls — bounded by replay_syscall_step's deactivation /
	 * sanitise checks, which drop the chain on first unsafe step) or
	 * stick the ring lock (chain saves and replays stall fleet-wide
	 * until a kernel-side timeout reaps the holder).  No parent crash
	 * surface.
	 *
	 * Route through alloc_shared_pool so the default --guard-shared
	 * scope (pools) wraps this long-lived single-region ring in
	 * PROT_NONE guard pages.  A stray writer that over- or under-runs
	 * the region then faults at the write PC instead of silently
	 * corrupting a stored chain (next replay tail-truncates on the
	 * sanitise check but the scribble site is already lost) or stalling
	 * the ring lock until the kernel-side timeout fires.  Sibling
	 * minicorpus_shm, which is the analogous corpus-side wild-writer
	 * target, has been pool-routed; this lifts the same coverage to
	 * the chain-corpus ring without dragging a per-child VMA tail in
	 * (allocation is once, no per-fork multiplication).
	 */
	chain_corpus_shm = alloc_shared_pool(sizeof(struct chain_corpus_ring));
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
			case ARG_IOVEC_IN:
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
 *
 * Per-(reason, trigger_nr) admission cap: at most one admit per rotation
 * window.  The chain corpus is a single fleet-wide pool, so a hot syscall
 * that earns a non-PC novelty signal on every other call (CMP / transition
 * floods are the realistic shape) could otherwise sweep the ring's PC-
 * saved entries out inside one window.  Reading shm->syscalls_at_last_switch
 * and comparing against the per-(reason, nr) stamp turns that into "first
 * winner this window admits, the rest are dropped" without needing a
 * separate per-window counter that has to be reset on rotation.
 */
/* lookback depth for chain_corpus_save's duplicate-shape scan */
#define CHAIN_CORPUS_DUP_LOOKBACK 8

/* shape-hash for a chain: FNV-1a over (nr, do32bit) tuples,
 * length-included to avoid prefix aliasing */
static uint32_t chain_shape_hash(const struct chain_step *steps,
				 unsigned int len)
{
	uint32_t h = 0x811c9dc5u;
	unsigned int i;

	h ^= len;
	h *= 0x01000193u;
	for (i = 0; i < len; i++) {
		uint32_t v = (uint32_t)steps[i].nr;

		if (steps[i].do32bit)
			v |= 0x80000000u;
		h ^= v;
		h *= 0x01000193u;
	}
	return h;
}

void chain_corpus_save(const struct chain_step *steps, unsigned int len,
		       unsigned int reason, unsigned int trigger_nr)
{
	struct chain_corpus_ring *ring = chain_corpus_shm;
	struct chain_entry tmp;
	unsigned int slot, head, count;
	unsigned long window_id, prev_window;
	uint32_t incoming_hash;
	bool dup_seen = false;

	if (ring == NULL || len == 0 || len > MAX_SEQ_LEN)
		return;

	if (reason >= CHAIN_SAVE_NR_REASONS || trigger_nr >= MAX_NR_SYSCALL)
		return;

	if (!chain_is_replay_safe(steps, len))
		return;

	/* Per-(reason, nr) per-window cap.  Racing children in the same
	 * window may both observe a stale stamp and both admit -- the cap is
	 * a flood ceiling, not an exact-one-admit invariant, and the lock
	 * cost of CAS-tightening it would dwarf the avoided ring churn. */
	window_id = __atomic_load_n(&shm->syscalls_at_last_switch,
				    __ATOMIC_RELAXED);
	prev_window = __atomic_load_n(
		&ring->chain_save_window_id[reason][trigger_nr],
		__ATOMIC_RELAXED);
	if (prev_window == window_id && window_id != 0)
		return;
	__atomic_store_n(&ring->chain_save_window_id[reason][trigger_nr],
			 window_id, __ATOMIC_RELAXED);

	memset(&tmp, 0, sizeof(tmp));
	tmp.len = len;
	tmp.save_reason = reason;
	memcpy(tmp.steps, steps, len * sizeof(struct chain_step));

	incoming_hash = chain_shape_hash(steps, len);

	lock(&ring->lock);

	/* Walk up to CHAIN_CORPUS_DUP_LOOKBACK of the
	 * most-recent saved slots (excluding the still-empty
	 * incoming slot) and compare shape hashes.  Bounded by
	 * min(count, lookback) so a warm corpus pays the full
	 * lookback while a cold corpus pays only its filled depth.
	 * Done under ring->lock so the slot reads can't tear
	 * against a concurrent save publishing into the same slot
	 * range. */
	{
		unsigned int lookback = ring->count;
		unsigned int j;

		if (lookback > CHAIN_CORPUS_DUP_LOOKBACK)
			lookback = CHAIN_CORPUS_DUP_LOOKBACK;
		for (j = 0; j < lookback; j++) {
			unsigned int prev_slot =
				(ring->head - 1u - j) % CHAIN_CORPUS_RING_SIZE;
			const struct chain_entry *p = &ring->slots[prev_slot];

			if (p->len == 0 || p->len > MAX_SEQ_LEN)
				continue;
			if (chain_shape_hash(p->steps, p->len) == incoming_hash) {
				dup_seen = true;
				break;
			}
		}
	}

	head = ring->head;
	slot = head % CHAIN_CORPUS_RING_SIZE;
	ring->slots[slot] = tmp;

	/* Publish head/count with release semantics so the lockless
	 * chain_corpus_pick reader, which loads them with acquire, sees the
	 * slot writes that produced this entry.  The lock still serialises
	 * concurrent writers; the atomic stores only exist to give the
	 * lockless reader a well-defined view of the sequence fields. */
	__atomic_store_n(&ring->head, head + 1, __ATOMIC_RELEASE);
	count = ring->count;
	if (count < CHAIN_CORPUS_RING_SIZE)
		__atomic_store_n(&ring->count, count + 1, __ATOMIC_RELEASE);

	unlock(&ring->lock);

	__atomic_fetch_add(&ring->save_count, 1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(&ring->chain_save_by_reason[reason], 1UL,
			   __ATOMIC_RELAXED);
	if (dup_seen)
		__atomic_fetch_add(&shm->stats.chain_corpus_save_dup_shape,
				   1UL, __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(&shm->stats.chain_corpus_save_unique_shape,
				   1UL, __ATOMIC_RELAXED);
}

bool chain_corpus_pick(struct chain_entry *out)
{
	struct chain_corpus_ring *ring = chain_corpus_shm;
	unsigned int count, head, slot;

	if (ring == NULL || out == NULL)
		return false;

	/*
	 * Lockless reader.  Atomic-load a snapshot of count and head, then
	 * struct-copy the chosen slot without holding ring->lock.  The
	 * picker used to take ring->lock for the full chain_entry memcpy
	 * (~MAX_SEQ_LEN * sizeof(struct chain_step)), and CHAIN_REPLAY_RATIO
	 * routes ~25% of fuzzer iterations through here, so the lock used
	 * to be a non-trivial contention point with both child producers
	 * (chain_corpus_save) and child consumers fighting for it.
	 *
	 * Race tolerance: a concurrent chain_corpus_save can overwrite the
	 * slot we are mid-copy on, leaving @out with fields mixed from the
	 * old and the new chain.  The same risk is already documented in
	 * chain_corpus_init for wild-write corruption — replay_syscall_step
	 * drops the chain on the first deactivated/sanitise-tagged step,
	 * and a torn chain that survives those checks just dispatches one
	 * iteration's worth of slightly-corrupted args to the kernel, which
	 * is exactly what the fuzzer is doing on its other 75% of iterations
	 * anyway.  No reader-side validity invariant is broken: count is
	 * monotonic non-decreasing up to CHAIN_CORPUS_RING_SIZE so once we
	 * observe count > 0 the slot range is well-defined, and len is
	 * always written in [1, MAX_SEQ_LEN] so even a torn-read len can't
	 * walk @out->steps past its fixed-size array.
	 */
	count = __atomic_load_n(&ring->count, __ATOMIC_ACQUIRE);
	if (count == 0)
		return false;

	head = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE);

	/* Pick uniformly across the live entries.  The newest entry is
	 * at (head - 1), the oldest at (head - count); both wrap mod
	 * CHAIN_CORPUS_RING_SIZE. */
	slot = (head - count + rnd_modulo_u32(count)) % CHAIN_CORPUS_RING_SIZE;
	*out = ring->slots[slot];
	return true;
}

#if ENABLE_SEQUENCE_CHAIN

static unsigned int pick_chain_length(void)
{
	unsigned int r = rnd_modulo_u32(10);

	if (r < 3)
		return 2;
	if (r < 7)
		return 3;
	return 4;
}

/*
 * Cross-phase state for one run_sequence_chain() iteration.
 *
 * Filled by select_chain_source() (source pick + length), grown by
 * execute_chain_steps() (steps[] + per-chain novelty), then consumed by
 * record_chain_outcome() (save decision + replay-win credit).
 *
 * Per-chain novelty accounting tracks each save-reason category
 * separately so the chain admission decision can prefer PC over
 * TRANSITION over CMP -- the priority mirrors the per-call minicorpus
 * save tag (PC wins on calls where both PC and CMP fire), keeping the
 * chain corpus's reason mix interpretable alongside the per-call
 * corpus's saves_by_reason[] for the same event class.  trigger_nr_*
 * captures the syscall_nr of the FIRST step that fired each signal, so
 * chain_corpus_save's per-(reason, nr) per-window cap is bounded by the
 * actual triggering syscall and not the last step that happened to run.
 */
struct chain_run_state {
	struct chain_step steps[MAX_SEQ_LEN];
	unsigned int steps_recorded;

	struct chain_entry replay;
	unsigned int len;
	bool replaying;

	bool chain_found_new;
	bool chain_new_transition;
	bool chain_new_cmp;
	unsigned int trigger_nr_pc;
	unsigned int trigger_nr_transition;
	unsigned int trigger_nr_cmp;
};

static void select_chain_source(struct chain_run_state *s)
{
	/* With CHAIN_REPLAY_RATIO probability, try to replay a saved chain
	 * rather than generate a fresh one.  Falls back to fresh if the
	 * corpus is empty (warm-start) or if the picked chain is rejected
	 * mid-replay by replay_syscall_step's safety checks (deactivated
	 * syscall, sanitise that wasn't there at save time, etc.). */
	if (chain_corpus_shm != NULL && ONE_IN(CHAIN_REPLAY_RATIO) &&
	    chain_corpus_pick(&s->replay)) {
		/* chain_corpus_pick() is intentionally lockless and the
		 * ring lives in shared memory that fuzzed syscalls can
		 * scribble.  A torn read or a wild write into the slot's
		 * len field would let the loop below index past the
		 * fixed-size replay.steps[MAX_SEQ_LEN] before the per-
		 * step safety checks in replay_syscall_step ever ran.
		 * Reject the picked entry and fall back to a fresh chain
		 * if len escapes the [1, MAX_SEQ_LEN] range. */
		if (s->replay.len == 0 || s->replay.len > MAX_SEQ_LEN) {
			__atomic_fetch_add(&shm->stats.chain_replay_len_corrupt,
					   1UL, __ATOMIC_RELAXED);
			s->len = pick_chain_length();
		} else if (s->replay.save_reason != CHAIN_SAVE_PC &&
			   s->replay.save_reason < CHAIN_SAVE_NR_REASONS &&
			   !ONE_IN(CHAIN_REPLAY_NONPC_DOWNSAMPLE)) {
			/* Non-PC-saved chains replay at a lower rate than
			 * PC-saved ones until per-reason productivity data
			 * exists (chain_replay_win_by_reason).  Fall back to
			 * a fresh chain on the down-sampled half so the
			 * iteration still does useful work. */
			s->len = pick_chain_length();
		} else {
			s->replaying = true;
			s->len = s->replay.len;
			__atomic_fetch_add(&chain_corpus_shm->replay_count, 1UL,
					   __ATOMIC_RELAXED);
		}
	} else {
		s->len = pick_chain_length();
	}
}

static bool execute_chain_steps(struct childdata *child,
				struct chain_run_state *s)
{
	struct syscallrecord *rec = &child->syscall;
	bool have_substitute = false;
	unsigned long substitute_retval = 0;
	unsigned int i;

	for (i = 0; i < s->len; i++) {
		bool step_ret;
		bool step_found_new = false;
		unsigned long step_new_transition = 0;
		unsigned long step_new_cmp = 0;
		unsigned long rv;

		/* Mark steps i >= 1 of a fresh-generation chain as mid-chain
		 * so anything that wants to distinguish a chained dispatch
		 * from a standalone call can do so.  Step 0 and replay steps
		 * leave the flag clear. */
		child->in_chain_mid_step = (i > 0) && !s->replaying;

		if (s->replaying) {
			step_ret = replay_syscall_step(child,
						       &s->replay.steps[i],
						       have_substitute,
						       substitute_retval,
						       &step_found_new,
						       &step_new_transition,
						       &step_new_cmp);
			if (step_ret == FAIL) {
				/* Replay safety check failed (saved syscall
				 * has been deactivated or otherwise become
				 * unreplayable since save).  Drop into fresh
				 * generation for the rest of the chain so the
				 * iteration still does useful work.  The
				 * fallthrough fresh call is still step i, so
				 * re-evaluate the mid-chain flag after clearing
				 * replaying. */
				s->replaying = false;
				child->in_chain_mid_step = (i > 0);
				step_ret = random_syscall_step(child,
							       have_substitute,
							       substitute_retval,
							       &step_found_new,
							       &step_new_transition,
							       &step_new_cmp);
			}
		} else {
			step_ret = random_syscall_step(child,
						       have_substitute,
						       substitute_retval,
						       &step_found_new,
						       &step_new_transition,
						       &step_new_cmp);
		}

		/* Clear the flag immediately after dispatch so any non-chain
		 * picker invocation (e.g. random_syscall called from outside
		 * the chain executor on the next iteration of the main loop)
		 * cannot see a stale true value. */
		child->in_chain_mid_step = false;

		if (step_ret == FAIL)
			return FAIL;

		/* Snapshot the dispatched call into the chain buffer.  Done
		 * after dispatch returns so the args reflect any Phase 1
		 * retval substitution and the retval is the kernel's actual
		 * return.  cmp-mode steps have step_found_new == false
		 * (kcov_collect was skipped) — they still get recorded in
		 * the chain so saves preserve chain shape, but they don't
		 * by themselves trigger a chain save. */
		if (s->steps_recorded < MAX_SEQ_LEN) {
			struct chain_step *cs = &s->steps[s->steps_recorded++];

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

		if (step_found_new) {
			if (!s->chain_found_new)
				s->trigger_nr_pc = rec->nr;
			s->chain_found_new = true;
		}
		/* Per-step transition / CMP novelty.  Captured here on the
		 * SAME step record as the chain snapshot above so the trigger
		 * nr matches the syscall that actually fired the signal --
		 * keeps the per-(reason, nr) admit cap aligned with what the
		 * kernel-side counter actually observed. */
		if (step_new_transition > 0) {
			if (!s->chain_new_transition)
				s->trigger_nr_transition = rec->nr;
			s->chain_new_transition = true;
		}
		if (step_new_cmp > 0) {
			if (!s->chain_new_cmp)
				s->trigger_nr_cmp = rec->nr;
			s->chain_new_cmp = true;
		}

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

	return true;
}

static void record_chain_outcome(const struct chain_run_state *s)
{
	unsigned int reason;
	unsigned int trigger_nr;
	bool admit = true;

	/* Save chains that produced any novelty signal in any step.  The
	 * historical PC-only gate (chain_found_new) saved ~zero chains under
	 * a warm PC-edge plateau: at a 221k-edge fleet plateau the per-step
	 * PC novelty rate is near zero and the chain corpus sat idle (no
	 * saves, no replays) while the executor still spent the iter budget
	 * generating and dispatching chains.  Widening to TRANSITION /
	 * KCOV_CMP novelty parallels the per-call minicorpus save gate's
	 * earlier widening from PC-only to PC || CMP (see dispatch_step),
	 * keeping the chain corpus's "interesting input" definition aligned
	 * with the per-call corpus.  PC wins the tag when multiple signals
	 * fire on the same chain so the chain_save_by_reason[] historical
	 * accounting is comparable to minicorpus's saves_by_reason[].
	 *
	 * Length-1 chains aren't saved (trivially subsumed by the per-call
	 * minicorpus); the chain length floor of 2 from pick_chain_length()
	 * makes that condition redundant in practice but the explicit check
	 * keeps the contract obvious. */
	if (s->steps_recorded < 2)
		return;

	if (s->chain_found_new) {
		reason = CHAIN_SAVE_PC;
		trigger_nr = s->trigger_nr_pc;
	} else if (s->chain_new_transition) {
		reason = CHAIN_SAVE_TRANSITION;
		trigger_nr = s->trigger_nr_transition;
	} else if (s->chain_new_cmp) {
		reason = CHAIN_SAVE_CMP;
		trigger_nr = s->trigger_nr_cmp;
	} else {
		admit = false;
		reason = CHAIN_SAVE_NR_REASONS;
		trigger_nr = 0;
	}

	if (admit)
		chain_corpus_save(s->steps, s->steps_recorded, reason,
				  trigger_nr);

	/* Credit a replay "win" when every step of the dispatched
	 * chain came from the corpus and the chain earned any of the
	 * novelty signals above.  Gated on `replaying` (still true at
	 * loop exit means no replay_syscall_step FAIL forced a fresh-
	 * suffix fallback) so a fresh-suffix step's novelty cannot be
	 * mis-attributed to the picked entry's save_reason.
	 *
	 * The ratio chain_replay_win_by_reason[r] / chain_save_by_reason[r]
	 * is the productivity signal that drives the per-reason replay
	 * rate scaling in CHAIN_REPLAY_NONPC_DOWNSAMPLE. */
	if (chain_corpus_shm != NULL && s->replaying &&
	    (s->chain_found_new || s->chain_new_transition ||
	     s->chain_new_cmp) &&
	    s->replay.save_reason < CHAIN_SAVE_NR_REASONS)
		__atomic_fetch_add(
			&chain_corpus_shm->chain_replay_win_by_reason[
				s->replay.save_reason],
			1UL, __ATOMIC_RELAXED);
}

bool run_sequence_chain(struct childdata *child)
{
	struct chain_run_state state;

	memset(&state, 0, sizeof(state));

	select_chain_source(&state);

	if (execute_chain_steps(child, &state) == FAIL)
		return FAIL;

	/* Defensive: per-iteration clear inside the loop should have left
	 * the flag false on every exit, but a future early-return path
	 * could miss it.  Clearing once here at the end of the chain is
	 * cheap insurance against the next caller (post_run/syscall path
	 * outside the chain executor) observing a stale true. */
	child->in_chain_mid_step = false;

	record_chain_outcome(&state);

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
