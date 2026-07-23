/*
 * Mini-corpus core primitives: shm allocation + init, per-ring lock
 * bracket, replayability predicate, wp-canary sweep, mutator kill-
 * switch definition.  Shared surface exposed via
 * persist/minicorpus-internal.h.
 */

#include <stdlib.h>
#include <string.h>

#include "kcov.h"
#include "minicorpus.h"
#include "persist-util.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#include "minicorpus-internal.h"

struct minicorpus_shared *minicorpus_shm = NULL;

/*
 * Process-wide runtime kill switch for the mutator chain.  Set at init
 * from $TRINITY_DISABLE_MUTATORS=1 and inherited COW by every child.
 * When true, minicorpus_mutate_args() skips splice, xprop, and the
 * weighted-stack mutate steps and feeds the corpus entry through
 * verbatim (fd-safety scrub still runs).  Replay rates and corpus
 * promotion behaviour are otherwise unchanged, so an A/B between
 * enabled and disabled isolates the mutator chain's contribution to
 * iter rate and edge growth from the rest of the replay path.
 */
bool mutators_disabled;

void minicorpus_init(void)
{
	if (kcov_shm == NULL)
		return;

	/*
	 * Wild-write risk: a child syscall buffer pointer aliasing into
	 * the corpus could corrupt a saved snapshot's args[] (the next
	 * replay feeds garbage to the kernel — at worst ENOSYS / EINVAL,
	 * not a parent crash) or stick a ring->lock byte (one syscall's
	 * saves/replays stall).  The mut_attrib counters can be skewed
	 * but the weight floor (MUT_WEIGHT_FLOOR=50) keeps the scheduler
	 * operational.  No parent crash surface.
	 *
	 * Route through alloc_shared_pool so the default --guard-shared
	 * scope (pools) wraps this long-lived ~1.8 MB region in
	 * PROT_NONE guard pages.  A stray writer that over- or under-
	 * runs the region then faults at the write PC instead of
	 * silently corrupting saved snapshots and propagating the
	 * scribble into the next replay window.  Sibling kcov_shm has
	 * been pool-routed since the guard-armour landed; this lifts
	 * the same coverage to the corpus pool, which prior triages
	 * identified as a comparable wild-writer target.
	 */
	minicorpus_shm = alloc_shared_pool(sizeof(struct minicorpus_shared));
	memset(minicorpus_shm, 0, sizeof(struct minicorpus_shared));

	/* Stamp the writer-pinning canary in every ring.  Only writer of
	 * wp_canary, ever -- the per-syscall sweep (Stage 1) and the HW
	 * watchpoint (Stage 2) detect any subsequent write as the wild
	 * writer.  Stamp unconditionally so the field is initialised even
	 * when neither flag is in use (a future operator switching the
	 * flag on mid-stack would otherwise see a one-time false positive
	 * against the zero memset). */
	{
		unsigned int i;
		for (i = 0; i < MAX_NR_SYSCALL; i++)
			minicorpus_shm->rings[i].wp_canary = WP_CANARY_MAGIC;
	}

	output(0, "KCOV: mini-corpus allocated (%lu KB, %d entries/syscall)\n",
		(unsigned long) sizeof(struct minicorpus_shared) / 1024,
		CORPUS_RING_SIZE);

	xprop_build_whitelist();

	/* Mutator kill switch.  Honour only "1" -- any other value (empty,
	 * "0", arbitrary string) leaves mutators enabled, matching the
	 * least-surprise convention for boolean env gates elsewhere in
	 * trinity.  Logged unconditionally so the chosen mode is visible
	 * in the startup banner alongside the corpus init lines. */
	{
		const char *v = getenv("TRINITY_DISABLE_MUTATORS");

		mutators_disabled = (v != NULL && v[0] == '1' && v[1] == '\0');
		output(0, "KCOV: mini-corpus mutators=%s\n",
		       mutators_disabled ? "DISABLED" : "ENABLED");
	}
}

void minicorpus_ring_lock(struct corpus_ring *ring)
{
	if (minicorpus_shm != NULL)
		__atomic_fetch_add(&minicorpus_shm->held_count, 1,
				__ATOMIC_RELAXED);
	lock(&ring->lock);
}

void minicorpus_ring_unlock(struct corpus_ring *ring)
{
	unlock(&ring->lock);
	if (minicorpus_shm != NULL)
		__atomic_sub_fetch(&minicorpus_shm->held_count, 1,
				__ATOMIC_RELAXED);
}

/*
 * Whether a saved syscall's args can be replayed safely.  Rejects the
 * argtype set whose values are runtime-relative — replay either feeds
 * the kernel garbage or, for ARG_PID, an active pid that gets signalled.
 *
 *  - ARG_IOVEC / ARG_PATHNAME / ARG_SOCKADDR / ARG_MMAP: heap pointers
 *    handed out by generic_sanitise().  After deferred-free eviction
 *    they go stale and replay feeds freed memory to the kernel.
 *
 *  - ARG_PID: a pid valid in the saving run is meaningless in the
 *    replaying run.  Worse, dense trinity pid allocation plus kernel
 *    pid recycling means a stale pid frequently HITS a current trinity
 *    child or the parent — replay of kill / tkill / tgkill /
 *    pidfd_send_signal / rt_sigqueueinfo entries cascade-SIGKILLs the
 *    fleet.
 *
 * Three call sites must agree on this list:
 *
 *   minicorpus_save()       — refuse to capture in the first place.
 *   minicorpus_replay()     — refuse to play back from the in-memory
 *                             ring (catches cross-config corpus swap
 *                             where the ring contains entries built
 *                             for a different syscall set).
 *   minicorpus_load_file()  — refuse to admit from on-disk warm-start.
 *                             Covers stale corpora that predate the
 *                             ARG_PID guard, cross-config swap of a
 *                             saved file, and any future syscall whose
 *                             argtype changes to ARG_PID without
 *                             invalidating cached corpora.
 */
bool corpus_args_replayable(const struct syscallentry *entry)
{
	unsigned int i;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		switch (entry->argtype[i]) {
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
	return true;
}

bool minicorpus_wp_sweep(unsigned long *bad_addr, uint64_t *bad_val)
{
	struct corpus_ring *ring;
	unsigned int i;
	uint64_t observed;
	unsigned int cnt;

	if (minicorpus_shm == NULL)
		return false;

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		ring = &minicorpus_shm->rings[i];
		observed = ring->wp_canary;
		if (unlikely(observed != WP_CANARY_MAGIC)) {
			if (bad_addr != NULL)
				*bad_addr = (unsigned long) &ring->wp_canary;
			if (bad_val != NULL)
				*bad_val = observed;
			return true;
		}
		/* Documented invariant: count is bounded by the ring size.
		 * A scribble that lands in the count word (the count-word
		 * scribble case) inflates this past 32; surface it the same
		 * way. */
		cnt = ring->count;
		if (unlikely(cnt > CORPUS_RING_SIZE)) {
			if (bad_addr != NULL)
				*bad_addr = (unsigned long) &ring->count;
			if (bad_val != NULL)
				*bad_val = (uint64_t) cnt;
			return true;
		}
	}
	return false;
}
