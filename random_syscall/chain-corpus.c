/*
 * Sequence chain corpus (Phase 2): the in-memory ring of admitted chains
 * plus init / save / pick.  The rationale for a single fleet-wide ring
 * of inline chain_entry slots (instead of per-syscall banks or a
 * pointer table) and for keeping the pick path lockless lives inline at
 * the function bodies below and in the ring/entry declarations in
 * include/sequence.h.  On-disk persistence and the mid-run snapshot
 * cadence live next to this file in chain-persist.c; the chain
 * executor that generates and replays chains lives in chain-exec.c;
 * the resource-typing classifier and consumer table live in
 * chain-restype.c.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "child.h"
#include "kcov.h"
#include "params.h"
#include "random.h"
#include "rnd.h"
#include "sequence.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#include "chain-internal.h"

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
bool chain_is_replay_safe(const struct chain_step *steps,
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
