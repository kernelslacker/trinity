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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "persist-util.h"
#include "random.h"
#include "rnd.h"
#include "sequence.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"

#include "random_syscall/chain-internal.h"
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
	/* Resolve the resource-typing table once, alongside the ring
	 * allocation.  Runs unconditionally on both the kcov-shm and
	 * no-kcov-shm paths so an operator can pass
	 * --chain-resource-typing=shadow even on a build without KCOV
	 * for the classify counters alone (the ring is what needs
	 * kcov for save triggers -- classify itself does not).  Safe
	 * to call more than once; the tables are pure writes to
	 * static slots. */
	chain_restype_init();

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

	/*
	 * Cross-run warm-start.  Load any previously-saved chain corpus into
	 * the freshly-allocated ring before children fork so the load lands
	 * without racing the producers.  Failures (missing file, header
	 * mismatch, every entry rejected by re-validation) are silent -- a
	 * missing or stale image just means we boot cold, same policy the
	 * per-syscall minicorpus warm-start uses.  Gated on
	 * --no-chain-warm-start so an operator can opt out of the chain
	 * carrier independently of the other cross-run caches.
	 */
	if (!no_chain_warm_start) {
		const char *path = chain_corpus_default_path();

		if (path != NULL) {
			unsigned int loaded = 0, discarded = 0;

			if (chain_corpus_load_file(path, &loaded, &discarded))
				output(0, "chain corpus: warm-started %u chains from %s (%u discarded)\n",
				       loaded, path, discarded);
			else if (discarded != 0)
				output(0, "chain corpus: %u chains discarded from %s -- cold start\n",
				       discarded, path);

			/* Same path is reused as the mid-run snapshot target so
			 * a crash between warm-start and clean shutdown does
			 * not lose every chain admitted during the run.  The
			 * clean-exit save in trinity.c still fires on top of
			 * this to capture the trailing window of admits the
			 * periodic cadence had not yet flushed. */
			chain_corpus_enable_snapshots(path);
		}
	}
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
		__atomic_fetch_add(&shm->stats.chain_corpus.save_dup_shape,
				   1UL, __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(&shm->stats.chain_corpus.save_unique_shape,
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
	 * chain_entry copy is large (~MAX_SEQ_LEN * sizeof(struct chain_step)),
	 * and CHAIN_REPLAY_RATIO routes ~25% of fuzzer iterations through
	 * here, so keeping this path lockless avoids serialising producers
	 * (chain_corpus_save) and consumers on ring->lock.
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

	/* Producer-kind mask carried across steps of the same chain.
	 * Bit k set means at least one step so far in this chain
	 * classify_producer'd as kind k with a non-negative retval.
	 * Consulted by the next step's chain-restype hook (drives the
	 * consumer-bias override) and by record_chain_outcome's
	 * per-kind save/replay-win accounting. */
	unsigned int producer_kinds_seen;

	/* Producer-followed-by-consumer pair mask.  Bit k set means
	 * some step in this chain classify_producer'd as kind k AND a
	 * strictly-later step classify_consumer'd as kind k.  This is
	 * the mask record_chain_outcome uses to decide which
	 * chain_restype_save[k] / chain_restype_replay_win[k] slots to
	 * bump: a producer-only chain isn't the signal we're trying
	 * to reward. */
	unsigned int pair_kinds_seen;
};

/*
 * Chain-restype hook, run before dispatching step i (>= 1) whenever
 * some earlier step in this chain was classified as a resource
 * producer (producer_kinds_seen != 0).  Returns the biased NR to use
 * for this step (via @bias_nr_out) plus its do32bit flag; returns
 * false when either the mode does not permit an override, no kind in
 * the mask has a resolved consumer for the current dispatch arch, or
 * the accept-probability roll (LIVE only) rejected the override.
 *
 * The per-kind chain_restype_would_bias / chain_restype_biased
 * counters are bumped INSIDE this helper so the classifier's
 * observability lands whether or not the caller ultimately overrides
 * -- consistent with the "always-on classify counters" contract in
 * the mode-enum comment.  SHADOW never consumes RNG (the pick stream
 * stays byte-identical to OFF); LIVE consumes exactly two draws when
 * the accept passes (kind selection + consumer selection).
 */
static bool chain_restype_apply_bias(const struct chain_run_state *s,
				     bool do32bit_hint,
				     unsigned int *bias_nr_out,
				     bool *bias_do32_out)
{
	unsigned int mask = s->producer_kinds_seen;
	unsigned int k;
	int available[CHAIN_RESTYPE_NR];
	unsigned int navailable = 0;

	if (chain_resource_typing_mode == CHAIN_RESTYPE_MODE_OFF)
		return false;
	if (mask == 0)
		return false;

	/* Collect the kinds that (a) are set in mask and (b) have at
	 * least one resolved consumer NR for this arch.  A kind with
	 * an empty consumer table on the current arch cannot bias --
	 * counting it toward would_bias would inflate the measurement
	 * with picks we could never dispatch. */
	for (k = 0; k < CHAIN_RESTYPE_NR; k++) {
		if ((mask & (1u << k)) == 0)
			continue;
		if (!chain_restype_has_consumer((enum chain_resource_kind)k,
						do32bit_hint))
			continue;
		available[navailable++] = (int)k;
	}
	if (navailable == 0)
		return false;

	if (chain_resource_typing_mode == CHAIN_RESTYPE_MODE_SHADOW) {
		/* Shadow: count every available kind as "would_bias"
		 * without consuming RNG.  The pick stream stays
		 * identical to OFF; the counter only says "the LIVE arm
		 * would have had these kinds available to override
		 * with", which is the SHADOW mode's whole contract. */
		unsigned int i;

		for (i = 0; i < navailable; i++)
			__atomic_fetch_add(
				&shm->stats.chain_restype.would_bias[available[i]],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	/* LIVE.  Probabilistic bias: 50% of the time (ONE_IN(2)) we
	 * override, otherwise we let the plain random_syscall_step run
	 * so other links stay possible.  Rationale for 50%: we want
	 * strong enough steering that the productivity signal in
	 * chain_restype_replay_win is legible above the fresh-chain
	 * noise floor, without pinning the mid-chain slot to the
	 * consumer table -- 100% override would starve the discovery
	 * paths that Phase 1's uniform pick relies on. */
	if (!ONE_IN(2))
		return false;

	{
		enum chain_resource_kind chosen_kind =
			(enum chain_resource_kind)
			available[rnd_modulo_u32(navailable)];
		int consumer_nr = chain_restype_pick_consumer(chosen_kind,
							      do32bit_hint);

		if (consumer_nr < 0)
			return false;

		*bias_nr_out = (unsigned int)consumer_nr;
		*bias_do32_out = do32bit_hint;

		__atomic_fetch_add(
			&shm->stats.chain_restype.biased[chosen_kind],
			1UL, __ATOMIC_RELAXED);
		return true;
	}
}

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
			__atomic_fetch_add(&shm->stats.chain_restype.replay_len_corrupt,
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
		unsigned int bias_nr = 0;
		bool bias_do32 = false;
		bool use_bias = false;

		/* Mark steps i >= 1 of a fresh-generation chain as mid-chain
		 * so anything that wants to distinguish a chained dispatch
		 * from a standalone call can do so.  Step 0 and replay steps
		 * leave the flag clear. */
		child->in_chain_mid_step = (i > 0) && !s->replaying;

		/* Chain-restype hook.  Only fires for mid-chain fresh
		 * generation steps (i >= 1, !replaying) where a prior step
		 * classified as a producer.  In SHADOW/LIVE this bumps the
		 * per-kind observability counters; LIVE additionally hands
		 * back a specific consumer NR to override the picker with.
		 * Replay steps take the saved (nr, args) verbatim and are
		 * outside the bias contract -- overriding a replayed step's
		 * NR would break the replay contract with the corpus. */
		if (i > 0 && !s->replaying && s->producer_kinds_seen != 0) {
			bool do32_hint = biarch ? rec->do32bit : false;

			use_bias = chain_restype_apply_bias(s, do32_hint,
							    &bias_nr,
							    &bias_do32);
		}

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
		} else if (use_bias) {
			step_ret = random_syscall_step_biased(child,
							      bias_nr, bias_do32,
							      have_substitute,
							      substitute_retval,
							      &step_found_new,
							      &step_new_transition,
							      &step_new_cmp);
			if (step_ret == FAIL) {
				/* Biased NR became uncallable between the
				 * chain_restype_init resolve and now
				 * (deactivated, lost cap, AVOID_SYSCALL).
				 * Fall back to plain fresh dispatch so the
				 * slot still runs; the chain_restype_biased
				 * counter already bumped so a spike in
				 * fall-backs will surface as fresh dispatch
				 * counters advancing faster than the biased
				 * counter's downstream chain_restype_save
				 * numerator. */
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

		/* Chain-restype classifier.  Runs unconditionally after
		 * every dispatched step -- classify itself is cheap (a
		 * handful of NR compares) and the OFF gate lives inside
		 * chain_restype_apply_bias, not here, so
		 * chain_restype_produced remains an always-on
		 * observability counter.  Producer classify runs on the
		 * step's ACTUAL dispatched args + retval so socket-tcp's
		 * (family, type) check and bpf-map-fd's cmd check see
		 * what the kernel actually got.  Non-OFF only: OFF must
		 * stay byte-identical to today, including the counter
		 * writes -- an OFF run must not perturb shm->stats fields
		 * that a follow-up A/B differences against a pre-row
		 * baseline. */
		if (chain_resource_typing_mode != CHAIN_RESTYPE_MODE_OFF) {
			unsigned long step_args[6] = {
				rec->a1, rec->a2, rec->a3,
				rec->a4, rec->a5, rec->a6,
			};
			int pkind = chain_restype_classify_producer(
					rec->nr, rec->do32bit,
					step_args, rec->retval);
			unsigned int k;

			if (pkind >= 0) {
				__atomic_fetch_add(
					&shm->stats.chain_restype.produced[pkind],
					1UL, __ATOMIC_RELAXED);
				s->producer_kinds_seen |= (1u << pkind);
			}

			/* Pair detection.  For every producer kind already
			 * seen in this chain, check whether THIS step is a
			 * consumer of that kind.  Bit set means the chain
			 * carried a producer->consumer pair, which is the
			 * chain_restype_save[k] / chain_restype_replay_win[k]
			 * gate at record_chain_outcome time. */
			for (k = 0; k < CHAIN_RESTYPE_NR; k++) {
				if ((s->producer_kinds_seen & (1u << k)) == 0)
					continue;
				if (chain_restype_classify_consumer(
					    (enum chain_resource_kind)k,
					    rec->nr, rec->do32bit,
					    step_args) >= 0)
					s->pair_kinds_seen |= (1u << k);
			}
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

	/* Per-resource-kind chain_restype_save / chain_restype_replay_win
	 * accounting.  Gated on pair_kinds_seen (producer + consumer of
	 * the same kind both appeared in the chain) rather than the
	 * looser producer_kinds_seen: a chain that carried an
	 * epoll_create1 with no downstream epoll_ctl / epoll_wait step
	 * did not exercise the pair the LIVE bias is trying to build,
	 * and counting it toward chain_restype_save would inflate the
	 * denominator that chain_restype_replay_win is measuring
	 * productivity against.  OFF mode's classifier never runs, so
	 * pair_kinds_seen is zero and both loops skip -- no
	 * shm->stats mutation on the OFF path. */
	if (s->pair_kinds_seen != 0) {
		unsigned int k;

		if (admit) {
			for (k = 0; k < CHAIN_RESTYPE_NR; k++) {
				if ((s->pair_kinds_seen & (1u << k)) == 0)
					continue;
				__atomic_fetch_add(
					&shm->stats.chain_restype.save[k],
					1UL, __ATOMIC_RELAXED);
			}
		}

		if (s->replaying &&
		    (s->chain_found_new || s->chain_new_transition ||
		     s->chain_new_cmp)) {
			for (k = 0; k < CHAIN_RESTYPE_NR; k++) {
				if ((s->pair_kinds_seen & (1u << k)) == 0)
					continue;
				__atomic_fetch_add(
					&shm->stats.chain_restype.replay_win[k],
					1UL, __ATOMIC_RELAXED);
			}
		}
	}

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

/*
 * On-disk chain corpus format.
 *
 * A tiny fixed-size header followed by a stream of length-prefixed
 * chain entries.  Each entry carries the chain length, save-reason,
 * every step's (nr, do32bit, args, retval), and a CRC32 covering the
 * entry payload -- a corrupt entry is dropped without taking down the
 * whole file.
 *
 * Format is arch-tagged and kernel-release-tagged: chain corpora built
 * for a different arch or a different compiled kernel image are
 * refused at load time, since syscall numbers and kernel behaviour
 * both change under those variables and a mismatched replay would
 * feed the kernel argument tuples from a completely different
 * dispatch table.  Same policy the per-syscall minicorpus file uses,
 * with a distinct magic so a mis-pointed path can never load one
 * carrier's image into the other's parser.
 */
#define CHAIN_CORPUS_FILE_MAGIC		0x54524e43U /* "TRNC" */
#define CHAIN_CORPUS_FILE_VERSION	1U

/* Linux utsname fields are __NEW_UTS_LEN+1 = 65 bytes including NUL. */
#define CHAIN_CORPUS_UTSNAME_LEN	65

struct chain_corpus_file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t kernel_major;
	uint32_t kernel_minor;
	uint32_t max_nr_syscall;
	uint32_t max_seq_len;
	uint32_t reserved0;
	uint32_t reserved1;
	/* Full utsname.release and utsname.version strings.  release
	 * encodes the patch sublevel and any local version suffix; version
	 * encodes the build timestamp + git hash for builds that include
	 * them.  Strict equality on both means "same compiled kernel image"
	 * -- the only safe granularity for chain replay, since e.g.
	 * 7.0 vs 7.0-rc1 can differ in syscall behaviour despite matching
	 * major.minor. */
	char kernel_release[CHAIN_CORPUS_UTSNAME_LEN];
	char kernel_version[CHAIN_CORPUS_UTSNAME_LEN];
};

struct chain_corpus_file_step {
	uint32_t nr;
	uint32_t do32bit;	/* 0 or 1 -- wider slot for header stability */
	uint64_t args[6];
	uint64_t retval;
};

struct chain_corpus_file_entry {
	uint32_t len;
	uint32_t save_reason;
	struct chain_corpus_file_step steps[MAX_SEQ_LEN];
	uint32_t crc;
	uint32_t pad;
};

static bool chain_parse_kernel_version(const char *release,
				       uint32_t *major, uint32_t *minor)
{
	unsigned long maj, min;
	char *end;

	errno = 0;
	maj = strtoul(release, &end, 10);
	if (end == release || *end != '.' || errno == ERANGE)
		return false;

	release = end + 1;
	errno = 0;
	min = strtoul(release, &end, 10);
	if (end == release || errno == ERANGE)
		return false;

	*major = (uint32_t)maj;
	*minor = (uint32_t)min;
	return true;
}

static bool chain_current_kernel_version(uint32_t *major, uint32_t *minor)
{
	struct utsname u;

	if (uname(&u) != 0)
		return false;
	return chain_parse_kernel_version(u.release, major, minor);
}

bool chain_corpus_save_file(const char *path)
{
	struct chain_corpus_ring *ring = chain_corpus_shm;
	struct chain_corpus_file_header hdr;
	struct chain_entry snapshot[CHAIN_CORPUS_RING_SIZE];
	char tmppath[PATH_MAX];
	unsigned int snap_count = 0;
	unsigned int oldest = 0;
	unsigned int i;
	int fd;
	int ret;

	if (ring == NULL || path == NULL)
		return false;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = CHAIN_CORPUS_FILE_MAGIC;
	hdr.version = CHAIN_CORPUS_FILE_VERSION;
	hdr.max_nr_syscall = MAX_NR_SYSCALL;
	hdr.max_seq_len = MAX_SEQ_LEN;
	if (!chain_current_kernel_version(&hdr.kernel_major, &hdr.kernel_minor))
		return false;
	{
		struct utsname u;

		if (uname(&u) != 0)
			return false;
		strncpy(hdr.kernel_release, u.release,
			sizeof(hdr.kernel_release) - 1);
		hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
		strncpy(hdr.kernel_version, u.version,
			sizeof(hdr.kernel_version) - 1);
		hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';
	}

	/*
	 * Snapshot the whole occupied slot range under ring->lock, then
	 * release before the disk write.  The chain corpus is a single
	 * global ring rather than a per-syscall bank, so the lock hold
	 * time is bounded by one memcpy of at most CHAIN_CORPUS_RING_SIZE
	 * chain_entry slots (~74 KiB total).  Callers on the writer path
	 * only stall for that copy window; the disk I/O runs unlocked.
	 */
	lock(&ring->lock);
	snap_count = ring->count;
	if (snap_count > CHAIN_CORPUS_RING_SIZE)
		snap_count = CHAIN_CORPUS_RING_SIZE;
	if (snap_count != 0) {
		oldest = (ring->head - snap_count) % CHAIN_CORPUS_RING_SIZE;
		for (i = 0; i < snap_count; i++) {
			unsigned int slot = (oldest + i) % CHAIN_CORPUS_RING_SIZE;

			snapshot[i] = ring->slots[slot];
		}
	}
	unlock(&ring->lock);

	/* Per-pid tmp suffix so racing savers (a periodic and a shutdown
	 * save landing in the same tick, or two independent operators)
	 * cannot open the same .tmp file with O_TRUNC and interleave
	 * writes into a corrupt blob.  Atomic rename still gives the final
	 * file all-or-nothing semantics. */
	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		       path, (int)getpid());
	if (ret < 0 || (size_t)ret >= sizeof(tmppath))
		return false;

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return false;

	/* Neutralise any fuzzer-installed umask so the save mode is 0644. */
	if (fchmod(fd, 0644) != 0) {
		(void)close(fd);
		(void)unlink(tmppath);
		return false;
	}

	if (write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;

	for (i = 0; i < snap_count; i++) {
		struct chain_corpus_file_entry ent;
		const struct chain_entry *src = &snapshot[i];
		unsigned int step;
		unsigned int j;

		/* Drop obviously-corrupt slots (torn writes, wild-write
		 * scribbles) at save time so a later load never sees a
		 * length that would walk past the file-side steps[]. */
		if (src->len == 0 || src->len > MAX_SEQ_LEN)
			continue;

		memset(&ent, 0, sizeof(ent));
		ent.len = src->len;
		ent.save_reason = src->save_reason;
		for (step = 0; step < src->len; step++) {
			ent.steps[step].nr = src->steps[step].nr;
			ent.steps[step].do32bit = src->steps[step].do32bit ? 1U : 0U;
			for (j = 0; j < 6; j++)
				ent.steps[step].args[j] =
					(uint64_t)src->steps[step].args[j];
			ent.steps[step].retval =
				(uint64_t)src->steps[step].retval;
		}

		ent.crc = crc32(&ent,
			offsetof(struct chain_corpus_file_entry, crc));

		if (write_all(fd, &ent, sizeof(ent)) < 0)
			goto fail;
	}

	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		(void)unlink(tmppath);
		return false;
	}

	if (rename(tmppath, path) != 0) {
		(void)unlink(tmppath);
		return false;
	}
	return true;

fail:
	(void)close(fd);
	(void)unlink(tmppath);
	return false;
}

/*
 * Re-validate a chain candidate against the CURRENT syscall table
 * before admitting it to the ring.  Rejects on:
 *   (a) any step nr >= MAX_NR_SYSCALL (out of range)
 *   (b) any step whose nr does not resolve to a live syscall entry
 *       in the active table (get_syscall_entry returns NULL --
 *       covers cross-config swap where the saved file was recorded
 *       against a different active-syscall set)
 *   (c) chain_is_replay_safe returns false (any step carries an
 *       argtype that is not safe to replay -- stale heap pointers,
 *       stale pids, sanitise-stashed pointers).
 *
 * This is the same predicate the save side uses in chain_corpus_save,
 * re-run here so a saved chain whose syscall table has since changed
 * (a syscall was deactivated, a sanitise callback was added, an
 * argtype was tightened to ARG_PID) cannot slip back into the ring
 * through the load path.
 */
static bool chain_load_entry_is_admissible(const struct chain_corpus_file_entry *ent)
{
	struct chain_step steps[MAX_SEQ_LEN];
	unsigned int i, j;

	if (ent->len == 0 || ent->len > MAX_SEQ_LEN)
		return false;
	if (ent->save_reason >= CHAIN_SAVE_NR_REASONS)
		return false;

	for (i = 0; i < ent->len; i++) {
		struct syscallentry *e;
		bool do32 = ent->steps[i].do32bit != 0;

		if (ent->steps[i].nr >= MAX_NR_SYSCALL)
			return false;
		e = get_syscall_entry(ent->steps[i].nr, do32);
		if (e == NULL)
			return false;

		steps[i].nr = ent->steps[i].nr;
		steps[i].do32bit = do32;
		for (j = 0; j < 6; j++)
			steps[i].args[j] = (unsigned long)ent->steps[i].args[j];
		steps[i].retval = (unsigned long)ent->steps[i].retval;
	}

	return chain_is_replay_safe(steps, ent->len);
}

bool chain_corpus_load_file(const char *path,
			    unsigned int *loaded, unsigned int *discarded)
{
	struct chain_corpus_ring *ring = chain_corpus_shm;
	struct chain_corpus_file_header hdr;
	struct chain_corpus_file_entry ent;
	uint32_t cur_major, cur_minor;
	unsigned int nloaded = 0;
	unsigned int ndiscarded = 0;
	ssize_t hn;
	int fd;

	if (loaded)
		*loaded = 0;
	if (discarded)
		*discarded = 0;

	if (ring == NULL || path == NULL)
		return false;

	persist_sweep_stale_tmp(path);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;

	hn = read_all(fd, &hdr, sizeof(hdr));
	if (hn != (ssize_t)sizeof(hdr)) {
		(void)close(fd);
		return false;
	}

	/* Refuse the whole file on any header-level mismatch.  Magic /
	 * version / ring-shape drift can silently change the on-disk
	 * layout, and admitting stale entries under a new schema would
	 * feed the ring garbage. */
	if (hdr.magic != CHAIN_CORPUS_FILE_MAGIC ||
	    hdr.version != CHAIN_CORPUS_FILE_VERSION ||
	    hdr.max_nr_syscall != MAX_NR_SYSCALL ||
	    hdr.max_seq_len != MAX_SEQ_LEN) {
		(void)close(fd);
		return false;
	}

	if (!chain_current_kernel_version(&cur_major, &cur_minor) ||
	    hdr.kernel_major != cur_major ||
	    hdr.kernel_minor != cur_minor) {
		(void)close(fd);
		return false;
	}

	{
		struct utsname u;

		if (uname(&u) != 0) {
			(void)close(fd);
			return false;
		}
		hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
		hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';
		if (strncmp(hdr.kernel_release, u.release,
			    sizeof(hdr.kernel_release)) != 0 ||
		    strncmp(hdr.kernel_version, u.version,
			    sizeof(hdr.kernel_version)) != 0) {
			(void)close(fd);
			return false;
		}
	}

	for (;;) {
		struct chain_entry *dst;
		unsigned int slot;
		unsigned int step;
		unsigned int j;
		unsigned int head, count;
		uint32_t want;
		ssize_t n;

		n = read_all(fd, &ent, sizeof(ent));
		if (n == 0)
			break;
		if (n != (ssize_t)sizeof(ent)) {
			ndiscarded++;
			break;
		}

		want = crc32(&ent,
			offsetof(struct chain_corpus_file_entry, crc));
		if (want != ent.crc) {
			ndiscarded++;
			continue;
		}

		if (!chain_load_entry_is_admissible(&ent)) {
			ndiscarded++;
			continue;
		}

		lock(&ring->lock);
		head = ring->head;
		slot = head % CHAIN_CORPUS_RING_SIZE;
		dst = &ring->slots[slot];
		memset(dst, 0, sizeof(*dst));
		dst->len = ent.len;
		dst->save_reason = ent.save_reason;
		for (step = 0; step < ent.len; step++) {
			dst->steps[step].nr = ent.steps[step].nr;
			dst->steps[step].do32bit =
				ent.steps[step].do32bit != 0;
			for (j = 0; j < 6; j++)
				dst->steps[step].args[j] =
					(unsigned long)ent.steps[step].args[j];
			dst->steps[step].retval =
				(unsigned long)ent.steps[step].retval;
		}

		/* Publish head/count with release semantics so the
		 * lockless chain_corpus_pick reader, which loads them
		 * with acquire, sees the slot writes that produced this
		 * entry.  Matches chain_corpus_save's ordering. */
		__atomic_store_n(&ring->head, head + 1, __ATOMIC_RELEASE);
		count = ring->count;
		if (count < CHAIN_CORPUS_RING_SIZE)
			__atomic_store_n(&ring->count, count + 1,
					 __ATOMIC_RELEASE);
		unlock(&ring->lock);

		__atomic_fetch_add(&ring->save_count, 1UL, __ATOMIC_RELAXED);
		nloaded++;
	}

	(void)close(fd);

	if (loaded)
		*loaded = nloaded;
	if (discarded)
		*discarded = ndiscarded;
	return nloaded > 0;
}

/*
 * Build a default per-arch, per-kernel-release chain corpus path under
 * $XDG_CACHE_HOME (or $HOME/.cache).  Creates the parent directory
 * tree on demand.  The returned pointer is owned by a static buffer.
 *
 * Arch- and release-tagged rather than sharing a global filename so a
 * cross-arch or cross-kernel invocation cannot accidentally load a
 * chain corpus whose syscall numbers or kernel behaviour do not match
 * the current run -- the header re-validation above would catch the
 * mismatch and drop the file, but partitioning at the path level
 * keeps the on-disk cache trivially bisectable by an operator.
 */
const char *chain_corpus_default_path(void)
{
	static char pathbuf[PATH_MAX];
	const char *xdg = getenv("XDG_CACHE_HOME");
	const char *home = getenv("HOME");
	char dir[PATH_MAX];
	const char *arch;
	struct utsname u;
	char *r;
	int ret;

#if defined(__x86_64__)
	arch = "x86_64";
#elif defined(__i386__)
	arch = "i386";
#elif defined(__aarch64__)
	arch = "aarch64";
#elif defined(__arm__)
	arch = "arm";
#else
	arch = "unknown";
#endif

	if (uname(&u) != 0)
		return NULL;
	for (r = u.release; *r; r++) {
		if (*r == '/')
			*r = '_';
	}

	if (xdg && xdg[0] == '/') {
		ret = snprintf(dir, sizeof(dir),
			       "%s/trinity/chain-corpus", xdg);
	} else if (home && home[0] == '/') {
		ret = snprintf(dir, sizeof(dir),
			       "%s/.cache/trinity/chain-corpus", home);
	} else {
		return NULL;
	}
	if (ret < 0 || (size_t)ret >= sizeof(dir))
		return NULL;

	/* mkdir -p the leaf directory.  EEXIST is acceptable; success is
	 * defined by the final directory existing, not by which racing
	 * creator won. */
	{
		char *p;
		mode_t saved_umask = umask(0);

		for (p = dir + 1; *p; p++) {
			if (*p == '/') {
				*p = '\0';
				if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
					*p = '/';
					(void)umask(saved_umask);
					return NULL;
				}
				*p = '/';
			}
		}
		if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
			(void)umask(saved_umask);
			return NULL;
		}
		(void)umask(saved_umask);
	}

	ret = snprintf(pathbuf, sizeof(pathbuf), "%s/%s-%s",
		       dir, arch, u.release);
	if (ret < 0 || (size_t)ret >= sizeof(pathbuf))
		return NULL;
	return pathbuf;
}

/*
 * Mid-run periodic snapshot state.  Parallel to cmp_hints_snapshot_*:
 * the enabled flag gates chain_corpus_maybe_snapshot() so the periodic
 * hook is a no-op until warm-start setup has resolved a valid path.
 *
 * The save trigger is driven off ring->save_count -- the same monotonic
 * atomic that chain_corpus_save() already increments on every admit --
 * so no new generation counter is needed on the ring itself.  Reading
 * it once per stats tick with RELAXED semantics is a single unsigned-
 * long load, well below the tick budget, and matches the
 * cmp_hints_total_generation() shape used for the analogous trigger on
 * the cmp-hints pool.
 */
static char chain_corpus_snapshot_path[PATH_MAX];
static bool chain_corpus_snapshot_enabled;
static unsigned long chain_corpus_save_count_at_last_snapshot;
static time_t chain_corpus_last_snapshot_time;

void chain_corpus_enable_snapshots(const char *path)
{
	size_t len;

	if (path == NULL)
		return;
	len = strlen(path);
	if (len == 0 || len >= sizeof(chain_corpus_snapshot_path))
		return;
	memcpy(chain_corpus_snapshot_path, path, len + 1);
	chain_corpus_snapshot_enabled = true;
	chain_corpus_last_snapshot_time = (time_t)(mono_ns() / 1000000000ULL);
	if (chain_corpus_shm != NULL)
		chain_corpus_save_count_at_last_snapshot =
			__atomic_load_n(&chain_corpus_shm->save_count,
					__ATOMIC_RELAXED);
	else
		chain_corpus_save_count_at_last_snapshot = 0;
}

void chain_corpus_maybe_snapshot(void)
{
	unsigned long saves_now;
	time_t now;

	if (!chain_corpus_snapshot_enabled || chain_corpus_shm == NULL)
		return;

	saves_now = __atomic_load_n(&chain_corpus_shm->save_count,
				    __ATOMIC_RELAXED);
	now = (time_t)(mono_ns() / 1000000000ULL);

	/* Both gates must expire before a snapshot fires: enough new admits
	 * (so we don't write a near-identical payload to disk) AND enough
	 * wall time (so a burst of admits doesn't trigger one save per
	 * second).  The generation gate stays quiet once the ring saturates
	 * and the per-(reason, nr) window cap dominates the admit rate; the
	 * time gate would then be the only limiter, so both gates are
	 * required to avoid the pathological "saturated ring, high time
	 * budget, thrashing the disk" case.  Mirrors the cmp_hints gate. */
	if (saves_now < chain_corpus_save_count_at_last_snapshot
			+ CHAIN_CORPUS_SNAPSHOT_NEW ||
	    now < chain_corpus_last_snapshot_time
			+ (time_t)CHAIN_CORPUS_SNAPSHOT_INTERVAL_SEC)
		return;

	if (chain_corpus_save_file(chain_corpus_snapshot_path)) {
		chain_corpus_save_count_at_last_snapshot = saves_now;
		chain_corpus_last_snapshot_time = now;
	}
}
