/*
 * Coverage-guided argument retention (mini-corpus).
 *
 * Stores syscall argument snapshots that discovered new KCOV edges.
 * During future arg generation for the same syscall, a stored
 * snapshot may be replayed with per-argument mutations to explore
 * nearby input space.
 *
 * Syscalls with sanitise callbacks or with arg types that carry
 * heap pointers (ARG_IOVEC, ARG_PATHNAME, ARG_SOCKADDR, ARG_MMAP)
 * are excluded — those pointers become stale after deferred-free
 * eviction, causing UAF on replay.
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "blob_corpus.h"
#include "child.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "persist-util.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "pids.h"

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
static bool mutators_disabled;

/*
 * Cross-syscall value propagation (xprop) source whitelist.
 *
 * Within-syscall splice shuffles values between arg slots of one
 * snapshot.  xprop extends the same idea across syscalls: with low
 * probability an arg of the target syscall is overridden with a value
 * pulled from a *different* syscall's corpus pool.  Most arg slots see
 * no benefit from foreign values -- the kernel cheaply rejects
 * type-incoherent garbage with -EINVAL and we burn iterations -- so the
 * initial whitelist is narrow: fd-consuming slots of the target draw
 * from fd-returning syscalls' pools.  That pairing has the highest
 * a-priori chance of producing a value that lands in a region of input
 * space the kernel will follow rather than reject outright.
 *
 * Built once from minicorpus_init() by walking the syscall table
 * (which select_syscall_tables() has already populated by the time
 * init_shm runs) and recording the nr of every syscall with
 * rettype == RET_FD whose argtype set is corpus-replayable.  Inherited
 * COW by every child fork.
 */
#define XPROP_RATIO 64
#define XPROP_FD_SRC_MAX 64

static unsigned int xprop_fd_src_nrs[XPROP_FD_SRC_MAX];
static unsigned int xprop_n_fd_src;

static void xprop_build_whitelist(void);

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
	output(0, "KCOV: mini-corpus xprop whitelist: %u fd-returning sources\n",
		xprop_n_fd_src);

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

static void ring_lock(struct corpus_ring *ring)
{
	if (minicorpus_shm != NULL)
		__atomic_fetch_add(&minicorpus_shm->held_count, 1,
				__ATOMIC_RELAXED);
	lock(&ring->lock);
}

static void ring_unlock(struct corpus_ring *ring)
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
static bool corpus_args_replayable(const struct syscallentry *entry)
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

static void xprop_consider_nr(unsigned int nr)
{
	struct syscallentry *e;

	if (xprop_n_fd_src >= XPROP_FD_SRC_MAX)
		return;
	e = get_syscall_entry(nr, false);
	if (e == NULL || e->rettype != RET_FD)
		return;
	if (!corpus_args_replayable(e))
		return;
	xprop_fd_src_nrs[xprop_n_fd_src++] = nr;
}

static void xprop_build_whitelist(void)
{
	unsigned int nr;

	for (nr = 0; nr < MAX_NR_SYSCALL; nr++)
		xprop_consider_nr(nr);
}

/*
 * Pull a value from a different syscall's seen-arg pool for use as arg
 * @arg_atype of the target syscall @nr.  Returns true and writes the
 * picked value to *val on a hit; false leaves *val untouched.  Only
 * fd-typed target slots are eligible -- the whitelist source pool is
 * the fd-returning-syscall set built at init.  Self-pairs are filtered
 * (within-syscall shuffling is the splice op's job).
 */
static bool minicorpus_pick_from_other_syscall(unsigned int nr,
					       enum argtype arg_atype,
					       unsigned long *val)
{
	struct corpus_ring *ring;
	unsigned int src_nr, slot, src_arg, num_args;
	unsigned int count, head;
	unsigned long picked;

	/* xprop attempt denominator.  Bumped once per
	 * entry regardless of outcome so the type-hit rate
	 * xprop_hits / xprop_attempts is directly readable, and
	 * the reject-cause breakdown below sums (with hits) to
	 * xprop_attempts minus the xprop_n_fd_src==0 early-out
	 * (the whitelist-uninitialised case, which is not a
	 * realised attempt). */
	if (xprop_n_fd_src == 0)
		return false;
	__atomic_fetch_add(&minicorpus_shm->xprop_attempts, 1UL,
			   __ATOMIC_RELAXED);
	if (!is_fdarg(arg_atype)) {
		__atomic_fetch_add(&minicorpus_shm->xprop_reject_target_not_fdarg,
				   1UL, __ATOMIC_RELAXED);
		return false;
	}

	src_nr = xprop_fd_src_nrs[rnd_modulo_u32(xprop_n_fd_src)];
	if (src_nr == nr) {
		__atomic_fetch_add(&minicorpus_shm->xprop_reject_src_self,
				   1UL, __ATOMIC_RELAXED);
		return false;
	}

	ring = &minicorpus_shm->rings[src_nr];

	/*
	 * Lockless reader.  Single slot, single arg, no joint snapshot
	 * across multiple entries -- drop ring->lock and synchronise on
	 * the writer's release-stores of count/head (see
	 * minicorpus_save_with_reason).  Writers still serialise on
	 * ring->lock; this reader just observes the published view.
	 *
	 * Ordering: the writer publishes count BEFORE head (the
	 * deliberate inversion vs chain_corpus_save documented at the
	 * publish site).  An acquire-load of count is the synchronisation
	 * edge -- it pairs with the writer's release-store of count and
	 * therefore makes the entry stores that preceded that store
	 * visible to us.  The head store happens *after* the count store
	 * in writer program order, so a count-acquire does not also
	 * synchronise the head bump; loading head relaxed can return a
	 * value one publish stale.  That is fine: a stale head still
	 * points one past a slot that was validly published in some
	 * earlier save, so we land on a legitimate xprop source -- "most
	 * recent" is a heuristic here, not a correctness invariant.
	 *
	 * Race tolerance: a concurrent minicorpus_save can overwrite the
	 * slot we are mid-read on.  num_args is validated in [1, 6] post-
	 * snapshot; a torn struct assignment that produces an out-of-
	 * range value just skips the pick, no retry -- same tolerance
	 * the fuzzer applies to the other 75%+ of mutated inputs.
	 * args[] is a fixed-size 6-element array, so reading
	 * args[src_arg] with src_arg < num_args <= 6 is memory-safe even
	 * if the underlying ulong was itself torn; the caller just gets
	 * a slightly-stale value, which is fuzz fodder either way.
	 */
	count = __atomic_load_n(&ring->count, __ATOMIC_ACQUIRE);
	if (count == 0) {
		__atomic_fetch_add(&minicorpus_shm->xprop_reject_src_empty,
				   1UL, __ATOMIC_RELAXED);
		return false;
	}
	head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);

	/* Newest entry: head points one past the last write.  Adding
	 * CORPUS_RING_SIZE before the subtract keeps the unsigned modulo
	 * well-defined when head is 0 on a wrapped ring. */
	slot = (head + CORPUS_RING_SIZE - 1) % CORPUS_RING_SIZE;

	num_args = ring->entries[slot].num_args;
	if (num_args == 0 || num_args > 6) {
		__atomic_fetch_add(&minicorpus_shm->replay_torn_rejects,
				   1UL, __ATOMIC_RELAXED);
		return false;
	}
	src_arg = rnd_modulo_u32(num_args);
	picked = ring->entries[slot].args[src_arg];

	*val = picked;
	__atomic_fetch_add(&minicorpus_shm->xprop_hits, 1UL,
			   __ATOMIC_RELAXED);
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

void minicorpus_save(struct syscallrecord *rec)
{
	/* Legacy entry point: callers that haven't been updated to thread
	 * an enum corpus_save_reason through still want PC-source
	 * accounting, matching the pre-CMP-save-gate behaviour. */
	minicorpus_save_with_reason(rec, CORPUS_SAVE_REASON_PC);
}

void minicorpus_save_with_reason(struct syscallrecord *rec,
				 enum corpus_save_reason reason)
{
	struct corpus_ring *ring;
	struct corpus_entry tmp;
	struct syscallentry *entry;
	unsigned int nr = rec->nr;
	unsigned int i;
	unsigned int cur_count;

	if (minicorpus_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;

	/* An out-of-range reason would index off the end of
	 * saves_by_reason[].  Drop the save rather than corrupt unrelated
	 * shm state -- the caller is buggy if this fires, so don't
	 * silently re-bucket it as PC either. */
	if ((unsigned int)reason >= CORPUS_SAVE_NR_REASONS)
		return;

	entry = get_syscall_entry(nr, rec->do32bit);
	if (entry == NULL)
		return;

	if (!corpus_args_replayable(entry))
		return;

	/* Build the entry on the stack unlocked.  None of this work touches
	 * shared state, so holding ring->lock across the arg copy and the
	 * argtype walk would serialise every other saver / replayer on this
	 * syscall's ring for no contention reason.  Zero the whole local
	 * struct so any future corpus_entry field is implicitly initialised
	 * rather than silently publishing uninitialised stack bytes. */
	memset(&tmp, 0, sizeof(tmp));
	tmp.args[0] = rec->a1;
	tmp.args[1] = rec->a2;
	tmp.args[2] = rec->a3;
	tmp.args[3] = rec->a4;
	tmp.args[4] = rec->a5;
	tmp.args[5] = rec->a6;
	tmp.num_args = entry->num_args;

	/* RedQueen-source provenance tag: read the current child's in_reexec
	 * recursion guard inside the save site rather than threading a new
	 * parameter through the random-syscall.c caller.  A NULL child (the
	 * parent post-mortem path is the only realistic caller; the normal
	 * dispatch_step save path always runs inside a child) leaves the
	 * default-zero rq_sourced from the memset above, which is the
	 * correct PC-source attribution for that case. */
	{
		struct childdata *cc = this_child();

		if (cc != NULL && cc->in_reexec)
			tmp.rq_sourced = true;
	}

	/* Errno-gradient provenance tag: the reason argument is the
	 * authoritative source.  Propagates through minicorpus_replay()
	 * into childdata::replay_errno_sourced so frontier_record_new_edge()
	 * can credit a downstream PC-edge win back to the errno-source
	 * save.  Decoupled from rq_sourced above: a single entry can't be
	 * both rq_sourced and errno_sourced (RedQueen captures happen on
	 * the in_reexec path with the PC/CMP reasons; errno saves happen
	 * from handle_syscall_ret with CORPUS_SAVE_REASON_ERRNO). */
	if (reason == CORPUS_SAVE_REASON_ERRNO)
		tmp.errno_sourced = true;

	/* Saved fd numbers are stale on replay — zero them out so mutate_arg
	 * gets a fresh fd rather than trying to reuse a closed one.  Same
	 * treatment for ARG_ADDRESS / ARG_NON_NULL_ADDRESS: raw user pointers
	 * from the saving run's address space are garbage in the replaying
	 * run, but the runtime can re-derive a valid writable page if the
	 * slot is zero. */
	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (is_fdarg(entry->argtype[i]) ||
		    entry->argtype[i] == ARG_ADDRESS ||
		    entry->argtype[i] == ARG_NON_NULL_ADDRESS)
			tmp.args[i] = 0;
	}

	ring = &minicorpus_shm->rings[nr];

	ring_lock(ring);
	ring->entries[ring->head % CORPUS_RING_SIZE] = tmp;
	/* Publish count BEFORE head, with release semantics.  The
	 * planned lockless burst-path reader snapshots count first,
	 * gates on count >= K_RECENT, then computes a slot offset from
	 * a snapshotted head.  If head were observed past count, the
	 * reader would compute against a stale base.  This diverges
	 * from chain_corpus_save()'s head-first ordering by design.
	 * Writers still serialise via ring->lock; the release-stores
	 * exist solely to give the future acquire-load reader a well-
	 * defined view paired with the entry store above. */
	cur_count = ring->count;
	if (cur_count < CORPUS_RING_SIZE)
		__atomic_store_n(&ring->count, cur_count + 1,
				 __ATOMIC_RELEASE);
	__atomic_store_n(&ring->head, ring->head + 1, __ATOMIC_RELEASE);
	ring_unlock(ring);

	__atomic_fetch_add(&minicorpus_shm->mutations, 1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(&minicorpus_shm->saves_by_reason[reason], 1UL,
			   __ATOMIC_RELAXED);
	/* Ring-overwrite count per incoming reason.  At
	 * a full ring, the save above displaced the oldest existing
	 * entry; bump indexed by the incoming reason so the ratio
	 * evicts_by_reason[r] / saves_by_reason[r] is the realised
	 * "fraction of reason-r saves that evicted" rate the
	 * stratified mini-corpus replay policy hangs on. */
	if (cur_count >= CORPUS_RING_SIZE)
		__atomic_fetch_add(&minicorpus_shm->evicts_by_reason[reason],
				   1UL, __ATOMIC_RELAXED);

	/* Per-syscall RedQueen-source save counter.  Bumped only when the
	 * provenance tag captured above is set, so the per-syscall total is
	 * directly comparable with the rq_sourced_pcedge_wins_per_syscall[]
	 * counter that frontier_record_new_edge() bumps for later PC-edge
	 * wins from this same provenance.  RELAXED: cumulative diagnostic,
	 * consumed only at periodic dump time. */
	if (tmp.rq_sourced)
		__atomic_fetch_add(
			&shm->stats.pc_edge_source.rq_saves[nr],
			1UL, __ATOMIC_RELAXED);

	/* Per-syscall errno-source save counter.  Mirror of the rq_sourced
	 * bump above, paired with errno_sourced_pcedge_wins_per_syscall[]
	 * that frontier_record_new_edge() bumps for later PC-edge wins
	 * traced back to an errno-source save. */
	if (tmp.errno_sourced)
		__atomic_fetch_add(
			&shm->stats.pc_edge_source.errno_saves[nr],
			1UL, __ATOMIC_RELAXED);

	/* Blob-content sibling: promote any pending blob stash from this
	 * dispatch's blob_fill() calls into the shared blob corpus.  The
	 * pending stash is process-local, populated per ARG_BUF_SIZED
	 * draw, and only reaches shared storage on this productive-save
	 * path -- an unpromoted pending is cleared at the top of the next
	 * generate_syscall_args() without ever hitting shared memory. */
	blob_corpus_promote_pending();
}

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
static unsigned int mut_attrib[MUT_NUM_OPS];

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
static unsigned int mut_structured_attrib[MUT_NUM_OPS];

/*
 * Process-local replay and splice attribution flags.
 *
 * Set by minicorpus_replay() when the respective event occurs; consumed
 * and cleared by minicorpus_mut_attrib_commit() to attribute wins without
 * needing a second pass over the call path.  Per-process — same
 * fork/single-threaded guarantee as mut_attrib[].
 */
static bool this_replay_ran;
static bool this_replay_spliced;
static bool this_replay_xprop;

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
static bool this_replay_source_tracked;
static unsigned int this_replay_source_nr;
static unsigned int this_replay_source_slot;
/* Source-entry age (distance-from-head, in slots) at
 * replay-pick time.  Stashed at minicorpus_replay() pick and consumed
 * by minicorpus_mut_attrib_commit() to bin replay_wins_by_age.  Same
 * per-process / fork-then-single-threaded guarantee as the other
 * this_replay_* stashes above; unsigned so an untracked-source
 * commit just sees 0 without touching the histogram (gated on
 * this_replay_source_tracked). */
static unsigned int this_replay_source_age;

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

/*
 * Floor on the per-case weight in the weighted scheduler.
 *
 * Weights are scaled to [0, 1000] (see weighted_pick_case() comment).
 * A floor of 50 keeps even a thoroughly-failed case at ~5% of a winning
 * case's weight, so it still gets picked occasionally.  Without a floor,
 * a case that produced zero wins after many trials would asymptote to
 * weight 0 and never be retried — and kernel state changes underneath
 * us, so a previously-dead case can become productive later.
 */
#define MUT_WEIGHT_FLOOR 50

/*
 * Pick a mutator case 0..MUT_NUM_OPS-1 weighted by historical productivity.
 *
 * Each case's weight is the Beta(1,1)-prior posterior mean of its success
 * rate, scaled to [0, 1000]:
 *
 *     w[op] = max(MUT_WEIGHT_FLOOR, (wins[op] + 1) * 1000 / (trials[op] + 2))
 *
 * Why this formula:
 *
 *  - The Beta(1,1) prior (uniform) gives every case w=500 on cold start
 *    when trials=wins=0, so we degrade gracefully to uniform random pick
 *    until evidence accumulates.  No special-casing for the empty-stats
 *    state, no warm-up phase to misconfigure.
 *
 *  - Add-one (Laplace) smoothing in the numerator and add-two in the
 *    denominator keep the formula well-defined at trials=0 and prevent a
 *    single early success from pinning a case to weight 1000.  It's the
 *    closed-form posterior mean of a Beta-binomial, not an ad-hoc fudge.
 *
 *  - We use the posterior MEAN rather than full Thompson sampling
 *    (Beta-distribution sampling).  Thompson would also work and be
 *    technically more exploration-aware, but it requires a Gamma
 *    sampler in libc that doesn't exist; the floor + uniform-prior
 *    combination here gives most of the same exploration benefit with
 *    a few lines of integer arithmetic.
 *
 *  - The floor is on the absolute weight, not on relative pick probability.
 *    With six cases and one heavily winning, the floored cases share the
 *    remaining mass — never starved, never dominant.
 *
 * Called once per primitive mutation (not once per syscall): a 4-deep
 * stack consults the scheduler four times.  All loads are __atomic
 * RELAXED — slightly stale fleet-wide counts are fine, the scheduler
 * is statistical not exact.
 */
static unsigned int weighted_pick_case(enum argtype atype)
{
	unsigned int weights[MUT_NUM_OPS];
	unsigned int total = 0;
	unsigned int r, accum, i;

	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t = __atomic_load_n(&minicorpus_shm->mut_trials[i],
						  __ATOMIC_RELAXED);
		unsigned long s = __atomic_load_n(&minicorpus_shm->mut_wins[i],
						  __ATOMIC_RELAXED);
		unsigned long w = ((s + 1) * 1000UL) / (t + 2UL);

		if (w < MUT_WEIGHT_FLOOR)
			w = MUT_WEIGHT_FLOOR;
		weights[i] = (unsigned int)w;
		total += weights[i];
	}

	/* Case 8 (fd-swap) only does anything useful on fd-typed slots —
	 * pulling a random pool fd into a non-fd arg would just look like
	 * a small-integer noise mutation.  Zero its weight for non-fd args
	 * so the scheduler doesn't waste pick budget on it (and so its
	 * trials/wins ratio stays a meaningful signal of fd-swap value). */
	if (!is_fdarg(atype)) {
		total -= weights[8];
		weights[8] = 0;
	}

	r = rnd_modulo_u32(total);
	accum = 0;
	for (i = 0; i < MUT_NUM_OPS; i++) {
		accum += weights[i];
		if (r < accum)
			return i;
	}
	return MUT_NUM_OPS - 1;
}

/*
 * SHADOW eligibility predicate for the Phase C.3 structure-aware arm
 * picker.  True iff the slot's argtype + arg_param payload would have
 * let try_structured_mutation() fire a type-aware variant for at least
 * one op -- i.e. the same gates that branch already enforces inline.
 * Kept here rather than reaching into try_structured_mutation() so the
 * shadow path can reject degenerate metadata (empty arglist, inverted
 * range) at the same coarse granularity the unstructured fallback
 * currently bypasses it at.
 */
static bool slot_is_structured(enum argtype atype,
		const struct arg_param *params)
{
	if (params == NULL)
		return false;

	switch (atype) {
	case ARG_LIST:
	case ARG_OP:
		return params->list.num != 0 && params->list.values != NULL;
	case ARG_RANGE:
		return params->range.hi >= params->range.low;
	default:
		return false;
	}
}

/*
 * Shadow variant of weighted_pick_case() that adds the existing
 * mut_structured_trials / mut_structured_wins per-op stats as a second
 * Beta arm alongside the live mut_trials / mut_wins arm and draws from
 * the doubled 2 * MUT_NUM_OPS pool.  The op index returned is the
 * arm's op (arm mod MUT_NUM_OPS); the caller treats arms 0..N-1 and
 * N..2N-1 as the same op for divergence accounting, because the live
 * picker only ever returns an op index.  Caller MUST have already
 * confirmed slot_is_structured() -- otherwise the structured half is
 * meaningless and would just double-count the unstructured arm.
 *
 * Uses a fresh rnd_modulo_u32() draw rather than re-using the live
 * picker's r: the doubled-pool total differs from the live total, so
 * the live r does not map onto the same arm interval.  Burns one
 * additional RNG step per shadow sample, which is negligible against
 * the per-call cost.
 *
 * The same fd-only zeroing applied to op 8 in the live picker is
 * applied to both arm copies of op 8 here, so a non-fd structured slot
 * cannot accidentally make the fd-swap op weight non-zero just because
 * the structured arm exists.
 */
static unsigned int weighted_pick_case_shadow_structured(enum argtype atype)
{
	unsigned int weights[2 * MUT_NUM_OPS];
	unsigned int total = 0;
	unsigned int r, accum, i;

	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t = __atomic_load_n(&minicorpus_shm->mut_trials[i],
						  __ATOMIC_RELAXED);
		unsigned long s = __atomic_load_n(&minicorpus_shm->mut_wins[i],
						  __ATOMIC_RELAXED);
		unsigned long w = ((s + 1) * 1000UL) / (t + 2UL);

		if (w < MUT_WEIGHT_FLOOR)
			w = MUT_WEIGHT_FLOOR;
		weights[i] = (unsigned int)w;
	}
	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t = __atomic_load_n(
			&minicorpus_shm->mut_structured_trials[i],
			__ATOMIC_RELAXED);
		unsigned long s = __atomic_load_n(
			&minicorpus_shm->mut_structured_wins[i],
			__ATOMIC_RELAXED);
		unsigned long w = ((s + 1) * 1000UL) / (t + 2UL);

		if (w < MUT_WEIGHT_FLOOR)
			w = MUT_WEIGHT_FLOOR;
		weights[MUT_NUM_OPS + i] = (unsigned int)w;
	}

	if (!is_fdarg(atype)) {
		weights[8] = 0;
		weights[MUT_NUM_OPS + 8] = 0;
	}

	for (i = 0; i < 2 * MUT_NUM_OPS; i++)
		total += weights[i];

	r = rnd_modulo_u32(total);
	accum = 0;
	for (i = 0; i < 2 * MUT_NUM_OPS; i++) {
		accum += weights[i];
		if (r < accum)
			return i % MUT_NUM_OPS;
	}
	return MUT_NUM_OPS - 1;
}

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

/*
 * Cross-arg splice ratio.  With probability 1/SPLICE_RATIO, an arg in
 * a replay starts from a sibling arg's snapshot value rather than its
 * own, before the per-arg mutator chain runs on it.
 *
 * Why splice within the same syscall (rather than across syscalls or
 * across snapshots): args within one syscall invocation share semantic
 * structure — flags fields tend to share bit-encodings, length fields
 * tend to share scale, fd fields tend to be related — and splicing
 * preserves that structure while shuffling which slot each value lands
 * in.  Cross-snapshot or cross-syscall splice would mostly produce
 * type-incoherent gibberish; intra-syscall keeps the splice on a chain
 * of values the kernel already validated together.
 *
 * 10% is conservative: too much splice and we lose the per-arg
 * locality the corpus is meant to preserve.  Tunable here without
 * touching call sites.
 */
#define SPLICE_RATIO 10

/*
 * Per-arg mutation stacking depth.
 *
 * Drawing inspiration from AFL's havoc stage, when we mutate an argument
 * we apply 1..STACK_MAX mutations in sequence rather than always exactly
 * one.  Stacking lets us reach states that no single mutator can produce
 * (e.g. bit-flip then add-delta then boundary-replace), which is where the
 * long-tail edges tend to live once the easy single-mutation neighbours
 * have been exhausted.
 *
 * STACK_MAX caps the chain so a single arg can't burn unbounded entropy
 * and so the mutated value keeps some relationship to the snapshot —
 * past ~4 mutations on a scalar the result is indistinguishable from a
 * fresh random value, at which point the corpus snapshot has stopped
 * doing useful guidance work.
 *
 * STACK_MAX is defined in minicorpus.h (shared with stats.c for the
 * stack_depth_histogram array bounds). */

/*
 * Apply a structure-aware variant of mutator @op to @val when the
 * arg's type carries enough metadata to define a "valid neighbour"
 * (ARG_LIST: bitmask vocabulary; ARG_OP: pick-one enum; ARG_RANGE:
 * bounded integer).  Returns true and writes through *val on
 * success; returns false to let the caller fall through to the
 * byte-level switch.
 *
 * Hard rule: coupled tags (ARG_FD / typed FDs / ARG_ADDRESS /
 * ARG_LEN / ARG_STRUCT_PTR_*) are intentionally absent from the
 * switch.  Field-level perturbation of those slots breaks invariants
 * the rest of the generator (fd validity, ptr<->len pairing,
 * address aliasing) is built to preserve, so structured mutation is
 * the wrong tool for them — they fall through to the unstructured
 * ops which already handle them safely.
 *
 * Per-op semantics within each structured type:
 *   ARG_LIST  (bitmask vocabulary in arg_params.list.values[]):
 *     0/6/7 (bit-flip, bswap-add, bswap-sub) -> XOR one listed bit
 *     1 (add)        -> set one listed bit
 *     2 (sub)        -> clear one listed bit
 *     3 (boundary)   -> all listed bits OR'd, or zero
 *     4 (byte-shuf)  -> random subset of listed bits
 *     5 (keep)       -> no-op (still counts as structured firing)
 *   ARG_OP (pick-one vocabulary):
 *     1 (add)        -> next entry (index + 1)
 *     2 (sub)        -> prev entry (index - 1)
 *     3 (boundary)   -> first or last entry
 *     5 (keep)       -> no-op
 *     0/4/6/7        -> any different entry
 *   ARG_RANGE [low, hi]:
 *     1 (add)        -> +1 clamped to hi
 *     2 (sub)        -> -1 clamped to lo
 *     3 (boundary)   -> low or hi
 *     5 (keep)       -> no-op
 *     0/4/6/7        -> adjacent step (+/- 1) clamped
 *
 * Missing or degenerate metadata (NULL values array, num == 0, hi <
 * low) is treated as "no structure available" and the caller falls
 * through.
 */
static bool try_structured_mutation(unsigned long *val, unsigned int op,
		enum argtype atype, const struct arg_param *params)
{
	if (params == NULL)
		return false;

	switch (atype) {
	case ARG_LIST: {
		const struct arglist *list = &params->list;
		unsigned long bit;
		unsigned int j;

		if (list->num == 0 || list->values == NULL)
			return false;

		bit = list->values[rnd_modulo_u32(list->num)];

		switch (op) {
		case 0:
		case 6:
		case 7:
			*val ^= bit;
			return true;
		case 1:
			*val |= bit;
			return true;
		case 2:
			*val &= ~bit;
			return true;
		case 3: {
			unsigned long all = 0;

			if (RAND_BOOL()) {
				*val = 0;
			} else {
				for (j = 0; j < list->num; j++)
					all |= list->values[j];
				*val = all;
			}
			return true;
		}
		case 4: {
			unsigned long mask = 0;

			for (j = 0; j < list->num; j++)
				if (RAND_BOOL())
					mask |= list->values[j];
			*val = mask;
			return true;
		}
		case 5:
			return true;
		}
		return false;
	}
	case ARG_OP: {
		const struct arglist *list = &params->list;
		unsigned int cur, pick, j;

		if (list->num == 0 || list->values == NULL)
			return false;
		if (list->num == 1) {
			*val = list->values[0];
			return true;
		}

		cur = list->num;
		for (j = 0; j < list->num; j++) {
			if (list->values[j] == *val) {
				cur = j;
				break;
			}
		}

		switch (op) {
		case 1:
			pick = (cur < list->num) ?
				(cur + 1) % list->num :
				rnd_modulo_u32(list->num);
			*val = list->values[pick];
			return true;
		case 2:
			pick = (cur < list->num) ?
				(cur + list->num - 1) % list->num :
				rnd_modulo_u32(list->num);
			*val = list->values[pick];
			return true;
		case 3:
			*val = list->values[RAND_BOOL() ? 0 : list->num - 1];
			return true;
		case 5:
			return true;
		case 0:
		case 4:
		case 6:
		case 7:
			do {
				pick = rnd_modulo_u32(list->num);
			} while (pick == cur);
			*val = list->values[pick];
			return true;
		}
		return false;
	}
	case ARG_RANGE: {
		unsigned long lo = params->range.low;
		unsigned long hi = params->range.hi;

		if (hi < lo)
			return false;
		if (lo == hi) {
			*val = lo;
			return true;
		}

		switch (op) {
		case 1:
			*val = (*val >= hi) ? hi : *val + 1;
			return true;
		case 2:
			*val = (*val <= lo) ? lo : *val - 1;
			return true;
		case 3:
			*val = RAND_BOOL() ? lo : hi;
			return true;
		case 5:
			return true;
		case 0:
		case 4:
		case 6:
		case 7:
			if (RAND_BOOL())
				*val = (*val >= hi) ? hi : *val + 1;
			else
				*val = (*val <= lo) ? lo : *val - 1;
			return true;
		}
		return false;
	}
	default:
		return false;
	}
}

/*
 * Apply a small mutation to a single argument value.
 * The mutations are designed to explore nearby input space:
 *   - bit flip: toggle a uniform-random bit
 *   - add/sub:  adjust by a small delta (1..16)
 *   - boundary: replace with a boundary value (0, -1, page_size, etc.)
 *
 * Case selection is biased by historical productivity (see
 * weighted_pick_case()).  The selected case is recorded in mut_attrib[]
 * for post-syscall attribution by minicorpus_mut_attrib_commit().
 *
 * @params (when non-NULL) carries the ABI metadata for the slot --
 * arglist for ARG_LIST/ARG_OP, range for ARG_RANGE -- and lets the
 * picked op fire a type-aware variant instead of a byte-level
 * perturbation.  Structured firings are stashed in
 * mut_structured_attrib[op] alongside the unconditional mut_attrib[op]
 * bump so the commit path can separate structured vs unstructured
 * productivity per op.
 */
static unsigned long mutate_arg(unsigned long val, enum argtype atype,
		const struct arg_param *params)
{
	unsigned int op = weighted_pick_case(atype);

	/* SHADOW: on structured-eligible slots, compare the live op pick
	 * against what a doubled-pool picker (live arm + structured arm
	 * per op) would have chosen, and stamp the divergence rate into
	 * shm.  Does not change which op fires -- the live `op` above is
	 * what mut_attrib[]/try_structured_mutation()/the case switch all
	 * consume.  See struct minicorpus_shared mut_structured_shadow_*
	 * for the why; promoting structured arms to the live picker will
	 * consume this measurement.
	 *
	 * Arm-gated by the per-child mut_structured_arm_b stamp: Arm A
	 * (control) short-circuits before weighted_pick_case_shadow_
	 * structured() so mutate_arg's RNG sequence stays byte-identical
	 * to the pre-shadow (pre-139a829f) behaviour and the live
	 * weighted_pick_case() call above remains the only rnd_modulo_u32
	 * step on the picker path.  An unconditional shadow draw (the
	 * original 139a829f shape) burned an extra rnd_modulo_u32 on
	 * every structured-eligible slot fleet-wide, perturbing the live
	 * RNG with no clean control arm and making the divergence rate
	 * impossible to attribute against an unperturbed baseline. */
	{
		struct childdata *child = this_child();

		if (child != NULL && child->mut_structured_arm_b &&
		    minicorpus_shm != NULL &&
		    slot_is_structured(atype, params)) {
			unsigned int shadow_op =
				weighted_pick_case_shadow_structured(atype);

			__atomic_fetch_add(
				&minicorpus_shm->mut_structured_shadow_samples,
				1UL, __ATOMIC_RELAXED);
			if (shadow_op != op)
				__atomic_fetch_add(
					&minicorpus_shm->mut_structured_shadow_divergences,
					1UL, __ATOMIC_RELAXED);
		}
	}

	mut_attrib[op]++;

	if (try_structured_mutation(&val, op, atype, params)) {
		mut_structured_attrib[op]++;
		return val;
	}

	switch (op) {
	case 0:
		/* flip a uniform-random bit. */
		val ^= 1UL << rnd_modulo_u32(sizeof(unsigned long) * 8);
		break;
	case 1: {
		/* add small delta, saturate at ULONG_MAX */
		unsigned long delta = 1 + rnd_modulo_u32(16);
		val = ((unsigned long)-1 - val < delta) ? (unsigned long)-1 : val + delta;
		break;
	}
	case 2: {
		/* subtract small delta, saturate at 0 */
		unsigned long delta = 1 + rnd_modulo_u32(16);
		val = (val < delta) ? 0 : val - delta;
		break;
	}
	case 3:
		/* replace with boundary */
		val = get_boundary_value();
		break;
	case 4:
		/* byte-level shuffle: randomize one byte */
		{
			unsigned int byte_pos = rnd_modulo_u32(sizeof(unsigned long));
			unsigned long mask = 0xffUL << (byte_pos * 8);
			val = (val & ~mask) | ((unsigned long) RAND_BYTE() << (byte_pos * 8));
		}
		break;
	case 5:
		/* keep original — sometimes the saved value is good as-is */
		break;
	case 6: {
		/* endian-aware add: byte-swap at a width chosen by 50/33/17
		 * bias toward 32/16/64-bit, add a small delta in network-order
		 * interpretation, swap back.  Hits arithmetic neighbours of BE
		 * fields (sockaddr ports/addrs, raw IP headers, netfilter
		 * rules, netlink BE attrs) that native-endian add/sub misses
		 * because the magnitude byte sits at the opposite end of the
		 * word.  Width bias matches the prevalence of __be32/__be16/
		 * __be64 in the kernel API surface. */
		unsigned long delta = 1 + rnd_modulo_u32(16);
		unsigned int w = rnd_modulo_u32(6);
		if (w <= 2) {
			uint32_t v = __builtin_bswap32((uint32_t)val);
			val = (val & ~0xffffffffUL) |
			      __builtin_bswap32(v + (uint32_t)delta);
		} else if (w <= 4) {
			uint16_t v = __builtin_bswap16((uint16_t)val);
			val = (val & ~0xffffUL) |
			      __builtin_bswap16(v + (uint16_t)delta);
		} else {
			val = __builtin_bswap64(__builtin_bswap64(val) + delta);
		}
		break;
	}
	case 7: {
		/* endian-aware sub: mirror of case 6.  Subtracts in
		 * network-order interpretation; underflow wraps within the
		 * chosen width, which is fine — the resulting bit pattern is
		 * still an interesting boundary in the post-swap space. */
		unsigned long delta = 1 + rnd_modulo_u32(16);
		unsigned int w = rnd_modulo_u32(6);
		if (w <= 2) {
			uint32_t v = __builtin_bswap32((uint32_t)val);
			val = (val & ~0xffffffffUL) |
			      __builtin_bswap32(v - (uint32_t)delta);
		} else if (w <= 4) {
			uint16_t v = __builtin_bswap16((uint16_t)val);
			val = (val & ~0xffffUL) |
			      __builtin_bswap16(v - (uint16_t)delta);
		} else {
			val = __builtin_bswap64(__builtin_bswap64(val) - delta);
		}
		break;
	}
	case 8: {
		/* fd-pool cross-pollination.  Picked only for fd-typed args
		 * (weighted_pick_case() zeros this case for non-fd slots).
		 * With ~50% probability replace val with a different live fd
		 * drawn from the global pool — get_random_fd() picks across
		 * any active fd provider, so an ARG_FD_PIPE slot can land on
		 * a socket / io_uring / memfd / etc., exercising kernel paths
		 * that mix fd flavours (vmsplice between odd pairs, io_uring
		 * registering odd fds, fcntl on weird types).
		 *
		 * The other ~50% applies a small integer add inline, matching
		 * case 1's semantics: fd slots still see arithmetic-neighbour
		 * exploration so we don't lose the "off-by-one fd index"
		 * coverage that case 1 normally provides on this slot.
		 *
		 * If get_random_fd() returns a sentinel (-1, no providers; or
		 * a stdio fd 0/1/2 that the fd-safety pass downstream would
		 * patch anyway), fall through to the integer path so the
		 * mutation isn't a no-op.  Counts as one case-8 trial in the
		 * scheduler regardless of which branch fired. */
		bool swapped = false;

		if (RAND_BOOL()) {
			int fd = get_random_fd();

			if (fd > 2) {
				val = (unsigned long)fd;
				swapped = true;
			}
		}
		if (!swapped) {
			unsigned long delta = 1 + rnd_modulo_u32(16);
			val = ((unsigned long)-1 - val < delta) ?
			      (unsigned long)-1 : val + delta;
		}
		break;
	}
	}
	return val;
}

/*
 * Pick a stacking depth in [1, STACK_MAX] using a capped geometric
 * distribution with rate 1/2: P(1)=1/2, P(2)=1/4, P(3)=1/8, P(4)=1/8
 * (the tail mass collapses into the cap).  The bias toward small N
 * keeps most replays close to the corpus snapshot — only a minority
 * get aggressively stacked into deeper exploration.
 */
static unsigned int pick_stack_depth(void)
{
	unsigned int n = 1;

	while (n < STACK_MAX && RAND_BOOL())
		n++;
	return n;
}

/*
 * Apply mutate_arg n_muts times in sequence.  The stack composes the
 * primitive mutations into a single transformation per call site.
 * @params forwards the slot's ABI metadata so the structure-aware
 * variants can fire on every stacked step rather than just the first.
 */
static unsigned long mutate_arg_stacked(unsigned long val, unsigned int n_muts,
					enum argtype atype,
					const struct arg_param *params)
{
	while (n_muts-- > 0)
		val = mutate_arg(val, atype, params);
	return val;
}

/*
 * Apply the per-arg mutator chain (cross-arg splice + weighted-stack
 * mutate + fd safety) to args[6] in place, using @entry's argtype[]
 * for splice eligibility and fd substitution.  Both the per-syscall
 * mini-corpus replay path and the chain-corpus replay path call this
 * so the mutation logic — and the splice/replay/mut_attrib telemetry
 * it bumps — is a single shared engine.
 *
 * @nr is the syscall table index for the call whose args are being
 * mutated; consulted by the xprop branch to scope the cross-syscall
 * source pool.  Both callers already have the value (rec->nr /
 * saved->nr).
 *
 * Splice and mutate read from a local snapshot of the input so a
 * sibling arg's value used for splice is the original input, not an
 * already-mutated peer; matches the per-syscall behaviour.
 */
void minicorpus_mutate_args(unsigned long args[6], struct syscallentry *entry,
		unsigned int nr)
{
	unsigned long snapshot[6];
	unsigned int i;

	if (entry == NULL || minicorpus_shm == NULL)
		return;

	memcpy(snapshot, args, sizeof(snapshot));

	for (i = 0; i < entry->num_args && i < 6; i++) {
		unsigned long val = snapshot[i];

		/* Mutator kill switch.  When set via TRINITY_DISABLE_MUTATORS
		 * the corpus entry is replayed verbatim -- skip splice, xprop
		 * and the weighted-stack mutate.  The fd-safety scrub below
		 * still runs so stale stdio fds in the saved args don't slip
		 * through; that scrub is replay correctness, not mutation. */
		if (mutators_disabled)
			goto fd_safety;

		/* Cross-arg splice: with probability 1/SPLICE_RATIO, replace
		 * this arg's starting value with a sibling arg's value from
		 * the same snapshot.  Runs BEFORE the mutator chain so the
		 * spliced value gets mutated in place rather than passed
		 * straight through.  Requires num_args >= 2 (otherwise there
		 * is no other slot to splice from). */
		if (entry->num_args >= 2 && ONE_IN(SPLICE_RATIO)) {
			unsigned int offset = 1 +
				rnd_modulo_u32(entry->num_args - 1);
			unsigned int src = (i + offset) % entry->num_args;

			val = snapshot[src];
			__atomic_fetch_add(&minicorpus_shm->splice_hits,
					   1UL, __ATOMIC_RELAXED);
			this_replay_spliced = true;
		}

		/* Cross-syscall value propagation: with probability
		 * 1/XPROP_RATIO, override this arg with a value pulled from
		 * a *different* syscall's corpus pool.  Only fd-typed slots
		 * are eligible; the source set is the fd-returning-syscall
		 * whitelist built at init.  Runs after splice so an xprop
		 * hit displaces a spliced value rather than the other way
		 * round (xprop is the rarer event and its picked value is
		 * less likely to have been seen by the mutator before).  The
		 * downstream mutator chain still applies on top, matching
		 * splice's "starting value for the chain" semantics. */
		if (ONE_IN(XPROP_RATIO)) {
			unsigned long xval;

			if (minicorpus_pick_from_other_syscall(nr,
					entry->argtype[i], &xval)) {
				val = xval;
				this_replay_xprop = true;
			}
		}

		/* ~25% chance to mutate each arg.  When we do mutate, apply
		 * a stack of 1..STACK_MAX primitive mutations (geometric,
		 * biased toward small N) rather than a single one. */
		if (ONE_IN(4)) {
			unsigned int depth = pick_stack_depth();

			__atomic_fetch_add(&minicorpus_shm->stack_depth_histogram[depth],
					   1UL, __ATOMIC_RELAXED);
			val = mutate_arg_stacked(val, depth, entry->argtype[i],
					&entry->arg_params[i]);
		}

fd_safety:
		/* Don't let fd args land on stdin/stdout/stderr. */
		if (is_fdarg(entry->argtype[i]) && val <= 2)
			val = (unsigned long) get_random_fd();

		args[i] = val;
	}

	__atomic_fetch_add(&minicorpus_shm->replay_count, 1UL, __ATOMIC_RELAXED);
	this_replay_ran = true;
}

bool minicorpus_replay(struct syscallrecord *rec)
{
	struct corpus_ring *ring;
	struct corpus_entry snapshot;
	struct syscallentry *entry;
	unsigned int nr = rec->nr;
	unsigned int slot;

	if (minicorpus_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	ring = &minicorpus_shm->rings[nr];

	/* No saved entries yet. */
	if (ring->count == 0)
		return false;

	/* Phase 2 plateau intervention (cmp_rising_pc_flat): when the
	 * classifier has the fleet in the CMP-novelty-climbing /
	 * PC-edges-flat regime, the most recent K saves into any ring are
	 * by construction dominated by CORPUS_SAVE_REASON_CMP entries
	 * (the rule's own predicate says PC-source saves have stopped
	 * landing).  Narrow the slot picker to the K newest slots so
	 * replay biases toward the freshly-admitted CMP-source material
	 * without needing per-slot source tracking, and double the replay
	 * rate (25% -> 50%) so the new material actually gets exercised
	 * inside the plateau window.  Gate is a derived predicate over
	 * shm->plateau_current_hypothesis -- no latched flag; reverts
	 * automatically when the tick driver writes NONE or transitions
	 * to a different hypothesis. */
	const bool cmp_burst_active =
		__atomic_load_n(&shm->plateau_current_hypothesis,
				__ATOMIC_RELAXED) ==
		(int)PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT;
	const unsigned int K_RECENT = 8;

	/* Replay gate.  Default 25%; raised to 50% inside the burst. */
	if (cmp_burst_active) {
		if (!ONE_IN(2))
			return false;
	} else {
		if (!ONE_IN(4))
			return false;
	}

	if (cmp_burst_active) {
		/* Burst path lockless reader: picks one of K_RECENT newest
		 * slots, so the slot math needs a joint (head, count)
		 * snapshot.  The writer publishes count BEFORE head with
		 * release semantics (foundation commit), so acquire-loading
		 * count first is the synchronisation edge: it pairs with
		 * the entry stores that preceded the writer's count bump
		 * and chains the prior head bump that this count value
		 * implies.  Plain-load head next; release-store ordering
		 * guarantees the load sees a value at least as recent as
		 * what count implied.
		 *
		 * Race between count-load and head-load: a writer that
		 * publishes between the two leaves count snapshotted at
		 * the pre-publish value but head at the post-publish
		 * value, so the slot calc picks ONE entry newer than
		 * count implied.  That entry exists and is valid (the
		 * writer just published it), so num_args is sane --
		 * benign.  The reverse ordering (head before count) would
		 * be unsafe -- head could outrun count beyond the K_RECENT
		 * window and pick against a stale base.  Count-first
		 * acquire-load is load-bearing. */
		unsigned int count = __atomic_load_n(&ring->count,
						     __ATOMIC_ACQUIRE);
		unsigned int head, offset;

		if (count < K_RECENT)
			return false;

		head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
		offset = rnd_modulo_u32(K_RECENT);

		/* head points one past the most recently published slot,
		 * so (head - 1) is the newest and (head - K_RECENT) the
		 * oldest of the K_RECENT window. */
		slot = (head - K_RECENT + offset) % CORPUS_RING_SIZE;
		snapshot = ring->entries[slot];
		if (snapshot.num_args < 1 || snapshot.num_args > 6) {
			__atomic_fetch_add(&minicorpus_shm->replay_torn_rejects,
					   1UL, __ATOMIC_RELAXED);
			return false;
		}
		__atomic_fetch_add(&minicorpus_shm->cmp_rising_replay_picks,
				   1UL, __ATOMIC_RELAXED);
		this_replay_source_tracked = true;
		this_replay_source_nr = nr;
		this_replay_source_slot = slot;
		/* Source-entry age at pick.  In the
		 * K_RECENT-narrowed path the slot is the offset-th
		 * entry in the K_RECENT window ending at (head - 1),
		 * so age-from-head = K_RECENT - 1 - offset. */
		this_replay_source_age = (K_RECENT - 1u) - offset;
		{
			struct childdata *cc = this_child();

			if (cc != NULL) {
				cc->replay_rq_sourced = snapshot.rq_sourced;
				cc->replay_errno_sourced =
					snapshot.errno_sourced;
			}
		}
	} else {
		/* Common path: uniform over count, lockless.  The writer
		 * publishes count BEFORE head with release semantics, so
		 * an acquire-load on count pairs with the entry stores
		 * that preceded the writer's count bump.  The uniform-
		 * over-count slot pick doesn't reference head, so count
		 * is the only synchronisation edge we need.
		 *
		 * The struct-copy below is the atomic-from-fuzzer-
		 * perspective snapshot.  A torn read during a writer's
		 * slot-publish gives a 50-50 mix of two entries; the
		 * num_args validator post-copy catches the only
		 * consequential damage shape -- downstream args[i] reads
		 * going off-array.  Per the design doc this is no worse
		 * than the mutation noise the fuzzer applies to its other
		 * ~75%+ of iterations, so skip with no retry. */
		unsigned int count = __atomic_load_n(&ring->count,
						     __ATOMIC_ACQUIRE);

		/* Clamp to ring size before indexing.  count is an
		 * unsynchronised invariant on the writer side -- writers
		 * cap it at CORPUS_RING_SIZE -- but a torn or stomped
		 * count load could in principle return a value larger
		 * than the entries[] array.  The burst path above and
		 * the file-save path below both bound their slot picks
		 * by CORPUS_RING_SIZE; do the same here so a garbage
		 * count can't drive entries[slot] off-array.  In normal
		 * operation saves cap count at CORPUS_RING_SIZE, so this
		 * is a no-op on the hot path. */
		if (count > CORPUS_RING_SIZE)
			count = CORPUS_RING_SIZE;
		if (count == 0)
			return false;
		slot = rnd_modulo_u32(count);
		snapshot = ring->entries[slot];
		if (snapshot.num_args < 1 || snapshot.num_args > 6) {
			__atomic_fetch_add(&minicorpus_shm->replay_torn_rejects,
					   1UL, __ATOMIC_RELAXED);
			return false;
		}
		this_replay_source_tracked = true;
		this_replay_source_nr = nr;
		this_replay_source_slot = slot;
		/* Source-entry age = (head - 1 - slot)
		 * mod CORPUS_RING_SIZE.  Load head with RELAXED --
		 * the uniform-over-count slot pick above doesn't
		 * reference head, so this load is a measurement-only
		 * addition with no ordering constraint.  A stale
		 * head one publish behind just shifts the bin by one
		 * slot, which is well inside the bucket boundaries. */
		{
			unsigned int head_now = __atomic_load_n(
				&ring->head, __ATOMIC_RELAXED);

			this_replay_source_age =
				(head_now - 1u - slot) & (CORPUS_RING_SIZE - 1u);
		}
		{
			struct childdata *cc = this_child();

			if (cc != NULL) {
				cc->replay_rq_sourced = snapshot.rq_sourced;
				cc->replay_errno_sourced =
					snapshot.errno_sourced;
			}
		}
	}

	entry = get_syscall_entry(nr, rec->do32bit);
	if (entry == NULL)
		return false;

	if (!corpus_args_replayable(entry))
		return false;

	minicorpus_mutate_args(snapshot.args, entry, nr);

	rec->a1 = snapshot.args[0];
	rec->a2 = snapshot.args[1];
	rec->a3 = snapshot.args[2];
	rec->a4 = snapshot.args[3];
	rec->a5 = snapshot.args[4];
	rec->a6 = snapshot.args[5];

	return true;
}

/*
 * On-disk corpus persistence (warm-start).
 *
 * The format is a fixed header followed by a stream of fixed-size
 * entries.  Header carries a magic, a format version, the running
 * kernel's major.minor, and the syscall-number space size.  Each
 * entry carries the syscall number, num_args, six argument values,
 * and a CRC32 covering only the entry payload — a corrupt entry is
 * dropped without taking down the whole file.
 *
 * The layout is intentionally architecture-specific: callers build
 * paths under a per-arch subdirectory.  Cross-arch reuse is unsafe
 * because syscall numbers don't agree.
 */

#define CORPUS_FILE_MAGIC	0x54524E43U	/* "TRNC" */
#define CORPUS_FILE_VERSION	3U

/* Linux utsname fields are __NEW_UTS_LEN+1 = 65 bytes including NUL. */
#define CORPUS_UTSNAME_LEN	65

struct corpus_file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t kernel_major;	/* parsed from utsname.release, kept for diag */
	uint32_t kernel_minor;	/* same */
	uint32_t max_nr_syscall;
	uint32_t reserved;
	/* Full utsname.release and utsname.version strings.  release encodes
	 * the patch sublevel and any local version suffix (-rcN, -localN,
	 * vendor patches), version encodes the build timestamp + git hash
	 * for kernel builds that include them.  Strict equality on both
	 * means "same compiled kernel image" — the only safe granularity
	 * for replay, since e.g. 7.0 vs 7.0-rc1 can differ in syscall
	 * behavior despite matching major.minor. */
	char kernel_release[CORPUS_UTSNAME_LEN];
	char kernel_version[CORPUS_UTSNAME_LEN];
};

struct corpus_file_entry {
	uint32_t nr;
	uint32_t num_args;
	uint64_t args[6];
	uint32_t crc;
	uint32_t pad;
};

static bool parse_kernel_version(const char *release,
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

static bool current_kernel_version(uint32_t *major, uint32_t *minor)
{
	struct utsname u;

	if (uname(&u) != 0)
		return false;
	return parse_kernel_version(u.release, major, minor);
}

/*
 * Dirty-bit proxy for minicorpus_save_file().  Compared against
 * minicorpus_shm->mutations at the top of the save path; when equal,
 * no ring has been touched since the last successful save and the on-disk
 * image is bit-for-bit identical to what we would write.  Initialised to
 * ULONG_MAX so the first save in a process always fires; advanced on
 * every successful save and seeded by the warm-start loader so the
 * load-then-immediate-exit cycle skips its end-of-run save.
 *
 * Mostly-parent-private: the maybe_snapshot path runs in children but is
 * already throttled by its own CAS gate to roughly one save per
 * MINICORPUS_SNAPSHOT_EDGES window, so the worst case for a CAS-elected
 * child whose stale process-local baseline misses a true short-circuit
 * is bounded by that outer gate.  The redundant-save scenario this
 * commit targets is the parent end-of-run save, which is fully covered.
 */
static unsigned long minicorpus_mutations_at_last_save = ULONG_MAX;

bool minicorpus_save_file(const char *path)
{
	struct corpus_file_header hdr;
	struct corpus_file_entry ent;
	struct corpus_entry snapshot[CORPUS_RING_SIZE];
	char tmppath[PATH_MAX];
	unsigned long mutations_now;
	int fd;
	unsigned int nr;
	int ret;

	if (minicorpus_shm == NULL || path == NULL)
		return false;

	mutations_now = __atomic_load_n(&minicorpus_shm->mutations,
					__ATOMIC_RELAXED);
	if (mutations_now == minicorpus_mutations_at_last_save) {
		output(0, "minicorpus: snapshot skipped, no ring changes since last save\n");
		return true;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = CORPUS_FILE_MAGIC;
	hdr.version = CORPUS_FILE_VERSION;
	hdr.max_nr_syscall = MAX_NR_SYSCALL;
	if (!current_kernel_version(&hdr.kernel_major, &hdr.kernel_minor))
		return false;
	{
		struct utsname u;
		if (uname(&u) != 0)
			return false;
		strncpy(hdr.kernel_release, u.release, sizeof(hdr.kernel_release) - 1);
		hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
		strncpy(hdr.kernel_version, u.version, sizeof(hdr.kernel_version) - 1);
		hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';
	}

	/* Per-pid tmp suffix so a periodic save and the on-shutdown save
	 * can't open the same .tmp file with O_TRUNC and interleave their
	 * writes into a corrupt blob.  The atomic rename still gives the
	 * final on-disk file all-or-nothing semantics. */
	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d", path, (int)mypid());
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

	for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
		struct corpus_ring *ring = &minicorpus_shm->rings[nr];
		unsigned int snap_count, oldest, i;

		/* Lock briefly to copy the ring out into a local buffer, then
		 * release before the disk write.  Mid-run snapshots run while
		 * children are actively appending to rings; without the lock,
		 * head/count and entries[] can be read in inconsistent
		 * combinations.  Hold time is bounded by a memcpy of at most
		 * CORPUS_RING_SIZE entries (~1.8 KB), so per-ring writer stall
		 * is microseconds even under heavy contention. */
		ring_lock(ring);
		snap_count = ring->count;
		if (snap_count > CORPUS_RING_SIZE)
			snap_count = CORPUS_RING_SIZE;
		if (snap_count == 0) {
			ring_unlock(ring);
			continue;
		}
		oldest = (ring->head - snap_count) % CORPUS_RING_SIZE;
		for (i = 0; i < snap_count; i++) {
			unsigned int slot = (oldest + i) % CORPUS_RING_SIZE;
			snapshot[i] = ring->entries[slot];
		}
		ring_unlock(ring);

		for (i = 0; i < snap_count; i++) {
			struct corpus_entry *src = &snapshot[i];
			unsigned int j;

			memset(&ent, 0, sizeof(ent));
			ent.nr = nr;
			ent.num_args = src->num_args;
			for (j = 0; j < 6; j++)
				ent.args[j] = (uint64_t)src->args[j];

			ent.crc = crc32(&ent,
				offsetof(struct corpus_file_entry, crc));

			if (write_all(fd, &ent, sizeof(ent)) < 0)
				goto fail;
		}
	}

	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		unlink(tmppath);
		return false;
	}

	if (rename(tmppath, path) != 0) {
		unlink(tmppath);
		return false;
	}
	minicorpus_mutations_at_last_save = mutations_now;
	return true;

fail:
	close(fd);
	unlink(tmppath);
	return false;
}

bool minicorpus_load_file(const char *path,
		unsigned int *loaded, unsigned int *discarded)
{
	struct corpus_file_header hdr;
	struct corpus_file_entry ent;
	uint32_t cur_major, cur_minor;
	unsigned int nloaded = 0;
	unsigned int ndiscarded = 0;
	ssize_t hn;
	int fd;

	if (loaded)
		*loaded = 0;
	if (discarded)
		*discarded = 0;

	if (minicorpus_shm == NULL || path == NULL)
		return false;

	persist_sweep_stale_tmp(path);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			output(0, "minicorpus: no persisted state at %s -- cold start\n",
			       path);
		else
			output(0, "minicorpus: open(%s) failed: %s -- cold start\n",
			       path, strerror(errno));
		return false;
	}

	hn = read_all(fd, &hdr, sizeof(hdr));
	if (hn != (ssize_t)sizeof(hdr)) {
		output(0, "minicorpus: header truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, hn, sizeof(hdr));
		close(fd);
		return false;
	}

	if (hdr.magic != CORPUS_FILE_MAGIC ||
	    hdr.version != CORPUS_FILE_VERSION ||
	    hdr.max_nr_syscall != MAX_NR_SYSCALL) {
		close(fd);
		return false;
	}

	if (!current_kernel_version(&cur_major, &cur_minor) ||
	    hdr.kernel_major != cur_major ||
	    hdr.kernel_minor != cur_minor) {
		close(fd);
		return false;
	}

	{
		struct utsname u;
		if (uname(&u) != 0) {
			close(fd);
			return false;
		}
		/* Force NUL termination on the on-disk strings before strncmp,
		 * defensive against truncated/corrupt headers. */
		hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
		hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';
		if (strncmp(hdr.kernel_release, u.release,
			    sizeof(hdr.kernel_release)) != 0 ||
		    strncmp(hdr.kernel_version, u.version,
			    sizeof(hdr.kernel_version)) != 0) {
			close(fd);
			return false;
		}
	}

	for (;;) {
		struct corpus_ring *ring;
		struct corpus_entry *dst;
		struct syscallentry *xe;
		uint32_t want;
		ssize_t n;
		unsigned int j;
		unsigned int cur_count;

		n = read_all(fd, &ent, sizeof(ent));
		if (n == 0)
			break;
		if (n != (ssize_t)sizeof(ent)) {
			ndiscarded++;
			break;
		}

		want = crc32(&ent,
			offsetof(struct corpus_file_entry, crc));
		if (want != ent.crc || ent.nr >= MAX_NR_SYSCALL ||
		    ent.num_args < 1 || ent.num_args > 6) {
			ndiscarded++;
			continue;
		}

		/* Drop entries whose argtype set is no longer replay-safe.
		 * Catches stale-on-disk corpora pre-dating the ARG_PID guard,
		 * cross-config swap of a saved file (different syscall set
		 * for the same nr), and any future syscall whose argtype
		 * changes to ARG_PID without invalidating cached corpora.
		 * Bumps ndiscarded so operators see a corpus-quality signal
		 * rather than silently absorbing the entry.  do32bit isn't
		 * encoded on disk; the 64-bit table is the canonical view
		 * and on biarch any pointer/pid argtype is shared between
		 * both tables for a given nr. */
		xe = get_syscall_entry(ent.nr, false);
		if (xe != NULL && !corpus_args_replayable(xe)) {
			ndiscarded++;
			continue;
		}

		/* Mirror the save-side defence: zero out fd and address slots
		 * before they reach the ring.  Two cases the save-side can't
		 * cover: (a) on-disk corpora written by an older binary that
		 * predated the save-side zeroing, and (b) argtypes that have
		 * been tightened since the entry was saved (e.g. ARG_UNDEFINED
		 * → ARG_FD), where the saved literal is a stale fd from the
		 * recording run.  Predicate set matches the save-side loop so
		 * both ends agree on what counts as stale. */
		if (xe != NULL) {
			for (j = 0; j < ent.num_args && j < 6; j++) {
				if (is_fdarg(xe->argtype[j]) ||
				    xe->argtype[j] == ARG_ADDRESS ||
				    xe->argtype[j] == ARG_NON_NULL_ADDRESS)
					ent.args[j] = 0;
			}
		}

		ring = &minicorpus_shm->rings[ent.nr];
		ring_lock(ring);
		dst = &ring->entries[ring->head % CORPUS_RING_SIZE];
		for (j = 0; j < 6; j++)
			dst->args[j] = (unsigned long)ent.args[j];
		dst->num_args = ent.num_args;
		/* novel_replay_hits is volatile per-process baseline state,
		 * not persisted on disk.  Zero it explicitly when overwriting
		 * a recycled slot so an entry whose previous occupant had
		 * accumulated baseline doesn't inherit stale credit. */
		dst->novel_replay_hits = 0;
		/* Count-before-head release publish; see comment on the
		 * matching publish in minicorpus_save_with_reason(). */
		cur_count = ring->count;
		if (cur_count < CORPUS_RING_SIZE)
			__atomic_store_n(&ring->count, cur_count + 1,
					 __ATOMIC_RELEASE);
		__atomic_store_n(&ring->head, ring->head + 1,
				 __ATOMIC_RELEASE);
		ring_unlock(ring);
		__atomic_fetch_add(&minicorpus_shm->mutations, 1UL,
				   __ATOMIC_RELAXED);
		nloaded++;
	}

	close(fd);

	/* Seed the dirty-bit baseline so a load-then-immediate-exit cycle
	 * skips the redundant end-of-run save.  The load loop already bumped
	 * minicorpus_shm->mutations once per admitted entry, so the current
	 * counter exactly reflects the just-loaded state. */
	minicorpus_mutations_at_last_save =
		__atomic_load_n(&minicorpus_shm->mutations, __ATOMIC_RELAXED);

	if (loaded)
		*loaded = nloaded;
	if (discarded)
		*discarded = ndiscarded;
	return nloaded > 0;
}

/*
 * Build a default per-arch corpus path under $XDG_CACHE_HOME (or
 * $HOME/.cache).  Creates the parent directory tree on demand.  The
 * returned pointer is owned by a static buffer.
 */
const char *minicorpus_default_path(void)
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
		ret = snprintf(dir, sizeof(dir), "%s/trinity/corpus", xdg);
	} else if (home && home[0] == '/') {
		ret = snprintf(dir, sizeof(dir),
			"%s/.cache/trinity/corpus", home);
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

	ret = snprintf(pathbuf, sizeof(pathbuf), "%s/%s-%s", dir, arch, u.release);
	if (ret < 0 || (size_t)ret >= sizeof(pathbuf))
		return NULL;
	return pathbuf;
}

/*
 * Periodic mid-run snapshot trigger.
 *
 * The save path itself is set in the parent before fork via
 * minicorpus_enable_snapshots() and inherited COW by every child.  All
 * children call minicorpus_maybe_snapshot() after each kcov edge event;
 * the function early-returns cheaply unless the fleet-wide edge count
 * has advanced MINICORPUS_SNAPSHOT_EDGES past the last snapshot's
 * high-water-mark.  When the gap is reached, a single CAS on
 * minicorpus_shm->edges_at_last_snapshot picks one caller as the saver
 * — it runs minicorpus_save_file() while everyone else loses the CAS
 * and returns.  The next snapshot opportunity opens once the next
 * MINICORPUS_SNAPSHOT_EDGES window has accumulated.
 */
static char snapshot_path[PATH_MAX];
static bool snapshot_enabled;

void minicorpus_enable_snapshots(const char *path)
{
	size_t len;

	if (path == NULL)
		return;
	len = strlen(path);
	if (len == 0 || len >= sizeof(snapshot_path))
		return;
	memcpy(snapshot_path, path, len + 1);
	snapshot_enabled = true;

	/* Anchor the monotonic floor to fuzz-start so the first time-trigger
	 * fires MINICORPUS_SNAPSHOT_INTERVAL_SEC after enable rather than
	 * immediately on the first child's first call against an empty
	 * corpus.  CLOCK_MONOTONIC seconds: a wall-clock backward step would
	 * starve the cadence (now_sec never reaches old_time + interval),
	 * and a forward step would fire a burst of snapshots.  Defensive
	 * shm guard mirrors minicorpus_maybe_snapshot(). */
	if (shm != NULL)
		__atomic_store_n(&shm->stats.minicorpus_last_snapshot_time,
				 (unsigned long)(mono_ns() / 1000000000ULL),
				 __ATOMIC_RELAXED);
}

void minicorpus_maybe_snapshot(void)
{
	unsigned long edges_now, old, new_edges;
	unsigned long now_sec, old_time;
	bool edges_trigger, time_trigger;

	if (!snapshot_enabled || minicorpus_shm == NULL ||
	    kcov_shm == NULL || shm == NULL)
		return;

	edges_now = __atomic_load_n(&kcov_shm->edges_found, __ATOMIC_RELAXED);
	old = __atomic_load_n(&minicorpus_shm->edges_at_last_snapshot,
			      __ATOMIC_RELAXED);
	old_time = __atomic_load_n(&shm->stats.minicorpus_last_snapshot_time,
				   __ATOMIC_RELAXED);
	now_sec = (unsigned long)(mono_ns() / 1000000000ULL);

	edges_trigger = (edges_now >= old + MINICORPUS_SNAPSHOT_EDGES);
	time_trigger = (now_sec >= old_time + MINICORPUS_SNAPSHOT_INTERVAL_SEC);

	if (!edges_trigger && !time_trigger)
		return;

	/* Race for the slot.  Whoever wins the CAS is responsible for the
	 * save; the others see the new high-water-mark on their next call
	 * and early-return.  RELAXED ordering is enough — the save itself
	 * is independently consistent (per-ring lock during read), and the
	 * counter is just gating who runs, not what they observe.
	 *
	 * When only the time trigger fires, edges_now may equal `old` (no
	 * new edges since the last snapshot, but 5min has elapsed), and a
	 * CAS of (old -> old) would succeed for every concurrent caller
	 * rather than electing one.  Force the new value to be strictly
	 * greater in that case so the CAS is a real change and contested
	 * calls actually serialise.  The +1 skew on the next edge-trigger
	 * boundary is irrelevant against a 10000-edge window. */
	new_edges = (edges_now > old) ? edges_now : old + 1;
	if (!__atomic_compare_exchange_n(&minicorpus_shm->edges_at_last_snapshot,
					 &old, new_edges,
					 false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	minicorpus_save_file(snapshot_path);

	/* Advance the wall-clock baseline so the next time-trigger window
	 * starts cleanly regardless of which trigger fired this time.  No
	 * CAS needed: the window-CAS above already elected us as the sole
	 * writer for this snapshot boundary. */
	__atomic_store_n(&shm->stats.minicorpus_last_snapshot_time, now_sec,
			 __ATOMIC_RELAXED);
}
