/*
 * Mini-corpus save path: capture per-syscall argument snapshots into
 * the ring after a productive coverage signal.  Two entry points --
 * minicorpus_save() for legacy PC-source callers and
 * minicorpus_save_with_reason() for the reason-tagged path.
 */

#include <string.h>

#include "blob_corpus.h"
#include "child.h"
#include "minicorpus.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

#include "minicorpus-internal.h"

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

	minicorpus_ring_lock(ring);
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
	minicorpus_ring_unlock(ring);

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
