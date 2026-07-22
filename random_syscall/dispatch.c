/*
 * Prepare-and-dispatch the picked syscall and run its per-call post-
 * dispatch bookkeeping.  dispatch_step is the dense correctness
 * boundary where srec publication, fd accounting, kcov / CMP
 * collection, minicorpus save, and the greedy CMP RedQueen re-exec
 * cap all meet; random_syscall_step, replay_syscall_step,
 * random_syscall_step_biased, and random_syscall are the four
 * entry points that populate the record and call into it.
 *
 * All public entry points here (random_syscall, random_syscall_step,
 * random_syscall_step_biased, replay_syscall_step) are declared in
 * include/child.h; redqueen_reexec_step and the redqueen_pin_*
 * helpers are file-scope static.  Everything upstream of the raw
 * dispatch (pick, chain substitution, strategy accounting) lives in
 * the sibling random_syscall/ cluster files.
 */

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "arch.h"	// biarch
#include "arg-decoder.h"
#include "blob_mutator.h"
#include "child.h"
#include "cmp-frontier.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "debug.h"
#include "fd.h"
#include "kcov.h"
#include "locks.h"
#include "minicorpus.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "prop_ring.h"
#include "random.h"
#include "random-syscall-internal.h"
#include "reach-band.h"
#include "rnd.h"
#include "sequence.h"
#include "shm.h"
#include "signals.h"
#include "sanitise.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/* The per-pending-index success counter in kcov_shared is sized off
 * REEXEC_PENDING_PICK_HIST_NR (include/kcov.h); the per-call attribution
 * buffer it indexes is sized off MAX_REEXEC_PENDING (include/cmp_hints.h).
 * They MUST stay equal -- a wider counter under-uses the kcov_shm field
 * and a narrower one would let the clamped index drop the last slots'
 * success signal on the floor.  kcov.h does not include cmp_hints.h
 * (to stay self-contained), so the parity check lives here, where both
 * headers are in scope. */
_Static_assert(REEXEC_PENDING_PICK_HIST_NR == MAX_REEXEC_PENDING,
	       "REEXEC_PENDING_PICK_HIST_NR must equal MAX_REEXEC_PENDING");

/*
 * Greedy CMP RedQueen re-exec helper.  Forward-declared so dispatch_step's
 * tail can call it; definition lives after replay_syscall_step where the
 * fresh-args-then-pin-slot story is symmetric with the replay contract.
 *
 * pending_idx is the position in child->reexec_pending[] that the
 * consumer at the dispatch_step tail picked (0..reexec_pending_count);
 * carried through to the inner_new_cmp > 0 success block so the
 * per-pending-index success counter (kcov_shm->reexec_pending_hist.reexec_pending_pick_success[])
 * can be bumped at the chosen index without retaining the index in
 * per-child scratch.
 */
static bool redqueen_reexec_step(struct childdata *child,
				 const struct reexec_pending *p,
				 unsigned int pending_idx);

/*
 * Dispatch a fully-prepared syscallrecord and run the per-call
 * post-dispatch bookkeeping: kcov collection / cmp-hint collection,
 * edge-pair recording, mutator-attribution commit, mini-corpus save,
 * trace output, fd-ring update, group/last_syscall_nr tracking.
 *
 * Caller has already populated rec->nr, rec->do32bit, rec->a1..a6, the
 * postbuffer is already cleared, and any chain substitution has been
 * applied.  The two callers (random_syscall_step and replay_syscall_step)
 * differ only in how they got the args into rec; everything from
 * output_syscall_prefix forward is shared.
 */

static bool dispatch_step(struct childdata *child, struct syscallentry *entry,
			  bool *found_new, unsigned long *new_cmp_out,
			  unsigned long *new_transition_out)
{
	struct syscallrecord *rec = &child->syscall;
	bool new_edges;
	unsigned long new_edge_count = 0;

	/* Stamp the resolved entry on the rec so .sanitise / .post handlers
	 * (and helpers like this_syscallname()) can reach it without
	 * re-running get_syscall_entry(nr, do32bit) on every probe. */
	rec->entry = entry;

	/* Clear the per-call validator-reject flag.  do_syscall() sets this
	 * when validate_arg_coupling() rejects the call before the kernel is
	 * entered; the kcov_collect() gate below reads it to skip the
	 * total_calls / per_syscall_calls[nr] bumps that would otherwise
	 * poison kcov_syscall_cold_skip_pct() for strict-validator syscalls. */
	rec->validator_rejected = false;

	output_syscall_prefix(rec, entry);

	/* PC mode: per-child kcov fd collects edge coverage, optionally
	 * via KCOV_REMOTE_ENABLE to also pick up softirq / threaded-irq /
	 * kthread coverage triggered by this syscall.  CMP mode: per-child
	 * cmp fd collects comparison-operand records that feed the
	 * cmp_hints pool.  Mode is fixed at child init; remote_mode is
	 * only meaningful in PC mode (KCOV_REMOTE_ENABLE applies to the PC
	 * fd, not the cmp fd).
	 *
	 * Sample rate is per-syscall: calls whose interesting kernel work
	 * is deferred to kthreads / workqueues / softirqs (netlink async
	 * delivery, io_uring workers, BPF attach, mount workqueues, cgroup
	 * migration, namespace setup) are flagged with KCOV_REMOTE_HEAVY
	 * and sampled at the heavier 1-in-KCOV_REMOTE_RATIO_HEAVY rate so
	 * those deferred-work edges don't get stuck cold; everything else
	 * uses the default 1-in-KCOV_REMOTE_RATIO trickle. */
	if (child->kcov.mode == KCOV_MODE_PC) {
		/* When the kernel did not let this child enable KCOV_REMOTE,
		 * neither the static nor the adaptive policy can flip
		 * remote_mode true.  Match the historical short-circuit
		 * (which never invoked ONE_IN in that case) exactly so the
		 * caller's RNG stream stays byte-identical to the pre-row
		 * baseline for non-capable children. */
		if (!child->kcov.remote_capable) {
			child->kcov.remote_mode = false;
		} else {
			unsigned int remote_reciprocal =
				(entry->flags & KCOV_REMOTE_HEAVY) ?
					KCOV_REMOTE_RATIO_HEAVY :
					KCOV_REMOTE_RATIO;
			bool static_remote = ONE_IN(remote_reciprocal);
			/* The adaptive helper bumps shadow counters in
			 * lock-step from both A/B arms so the would-be
			 * divergence stays observable on Arm A (the control
			 * cohort) too.  Arm A then discards the adaptive
			 * disposition and runs the static decision so its
			 * live remote_mode is byte-identical to the pre-row
			 * baseline; Arm B substitutes the adaptive
			 * disposition as the live remote_mode. */
			bool adaptive_remote = remote_adaptive_decide(
				rec->nr, entry, static_remote);
			child->kcov.remote_mode = child->remote_adaptive_arm_b ?
				adaptive_remote : static_remote;
		}
	} else {
		child->kcov.remote_mode = false;
	}

	/*
	 * --self-corrupt-canary sentinel snapshot.  Deeper detector for
	 * mid-struct scribbles that leave the userspace-VA bracket the
	 * always-on gates check intact -- glibc-heap family aborts, an
	 * OBJ_LOCAL slot byte-flipped mid-record, etc.  Bounded XOR fold
	 * over child->local_stats + ->objects + kcov trace/cmp/dedup
	 * pointers + an 8-word magic-filled sentinel, computed here
	 * before dispatch and again right after so the delta names the
	 * syscall that produced the scribble.  Both branches gate on
	 * the OFF flag so a build without the row pays a single
	 * branch-predicted flag load per dispatch and nothing else --
	 * no function call, no memory read, no register spill.
	 */
	uint64_t canary_pre = 0;

	if (unlikely(self_corrupt_canary))
		canary_pre = self_corrupt_canary_signature(child);

	do_syscall(rec, entry, &child->kcov, child);

	if (unlikely(self_corrupt_canary)) {
		uint64_t canary_post = self_corrupt_canary_signature(child);

		if (canary_post != canary_pre)
			log_self_corrupt_culprit("canary:signature-delta",
				(unsigned long)(canary_pre ^ canary_post), rec);
	}

	/*
	 * Attribution overlay for the SELF-corruption cluster.  The
	 * kcov_local_stats_plausible() gates inside kcov_collect() and
	 * the objpool_check() gates in addr_in_local_runtime_map() will
	 * short-circuit the bad deref, but by the time they fire the
	 * current SREC on the innocent reader (kcov_collect, mmap-pool
	 * walker) has replaced the SREC of the syscall that produced
	 * the wild write.  Sample the per-child pointer state HERE --
	 * one syscall-return boundary after the write, still owning
	 * rec -- so the log names the actual culprit.  Same
	 * userspace-VA bracket kcov_local_stats_plausible() uses; a
	 * scribbled pointer that lands outside [0x10000, 2^47) is
	 * caught by the compare and logged.  child->local_stats and
	 * child->objects are the two pointers a sibling-side scribble
	 * has been observed to overwrite in the childdata region.
	 *
	 * Log-only: the downstream gates still run and still gate the
	 * deref, so a false-positive here (an unexpected NULL / low VA
	 * that is not actually the crash predecessor) costs one stderr
	 * line, not a crash or a behaviour change.  Does not consume
	 * RNG.  When both pointers are plausible (the overwhelming
	 * steady state) this block is a pair of userspace-VA range
	 * compares and nothing else.
	 */
	{
		uintptr_t ls = (uintptr_t)child->local_stats;
		uintptr_t ob = (uintptr_t)child->objects;

		if (!(ls >= 0x10000UL && ls < 0x800000000000UL))
			log_self_corrupt_culprit("dispatch:local_stats",
				(unsigned long)child->local_stats, rec);
		if (!(ob >= 0x10000UL && ob < 0x800000000000UL))
			log_self_corrupt_culprit("dispatch:objects",
				(unsigned long)child->objects, rec);
	}

	/* kcov_collect() returns the real per-call bucket-edge count via the
	 * out-param alongside its bool found_new return.  Diff-ing the global
	 * kcov_shm->coverage.edges_found around the call would race other children's
	 * concurrent increments and over-attribute their edges to this
	 * syscall; the per-call count is the authoritative number.
	 *
	 * CMP-mode children contribute zero PC edges (their PC fd is never
	 * enabled), so new_edge_count stays 0 and the per-strategy edge
	 * attribution block below naturally skips on its `new_edge_count > 0`
	 * gate.  Frontier ring updates and bandit reward attribution also
	 * skip cleanly via `if (new_edges)` further down -- CMP-mode
	 * children deliberately don't contribute to those PC-edge concepts.
	 *
	 * CMP-source corpus saves are the exception: kcov_collect_cmp
	 * returns the per-call count of bloom-novel KCOV_CMP_CONST
	 * comparisons, captured here in new_cmp.  Under a PC-edge plateau
	 * (cmp_rising_pc_flat) that count is the only available novelty
	 * signal -- the save gate below widens to `new_edges || new_cmp
	 * > 0` so the corpus can still grow and mutator wins can still be
	 * credited, breaking the self-reinforcing
	 * PC-plateau->no-saves->no-mutator-wins loop.  See
	 * investigations/corpus-mutator-zero-wins-2026-05-20 for the full
	 * analysis. */
	unsigned long new_cmp = 0;

	/* Snapshot the rescue classifier's cold-skip-pct input BEFORE
	 * kcov_collect runs.  On a new edge kcov_collect bumps
	 * last_edge_at[rec->nr] to the current total_calls, after which
	 * kcov_syscall_cold_skip_pct(rec->nr) returns 0 -- the exact case
	 * classify_random_rescue exists to recognise as RRC_COLD_SKIP.
	 * Reading it here, at draw time, keeps the classifier's "would the
	 * picker have skipped this?" question pinned to the picker's actual
	 * pre-call state.  Only meaningful in PC mode; the CMP path never
	 * reaches the classifier (new_edges stays false there). */
	unsigned int rescue_cold_skip_pct_before = 0;

	/* Initialised here so the transition-attribution block below (which
	 * runs unconditionally on the CMP-mode side too, gated on
	 * pcres.transition_edges_real_local > 0) sees a clean zero when
	 * the kcov_collect path is skipped. */
	struct kcov_pc_result pcres = { 0 };

	if (child->kcov.mode == KCOV_MODE_PC) {
		rescue_cold_skip_pct_before =
			kcov_syscall_cold_skip_pct(rec->nr);
		/* Pre-validation reject in do_syscall() -- the kernel was never
		 * entered, so there is no coverage to collect and bumping
		 * total_calls / per_syscall_calls[nr] inside kcov_collect()
		 * would poison kcov_syscall_cold_skip_pct() on syscalls whose
		 * validators are strict.  last_edge_at[] only moves on the
		 * found_new branch and stays correctly frozen here. */
		if (rec->validator_rejected)
			new_edges = false;
		else
			/* Pass &pcres (not NULL) so the per-strategy
			 * transition reward attribution below has access to
			 * pcres.transition_edges_real_local.  The bucket_bits
			 * / distinct_edges / local_distinct_pcs fields are
			 * also populated but the existing PC-edge attribution
			 * path consumes new_edge_count instead, so they are
			 * written but not read here -- the extra struct stores
			 * are zero-atomics and unmeasurable on the per-call
			 * cost. */
			new_edges = kcov_collect(&child->kcov, rec->nr,
						 rec->do32bit,
						 &new_edge_count, &pcres);
	} else {
		new_cmp = kcov_collect_cmp(&child->kcov, rec->nr,
					   rec->do32bit,
					   child->is_explorer,
					   child->strategy_at_pick);
		new_edges = false;

		account_reexec_ab_cohort(child, new_cmp);
	}

	account_per_syscall_new_edges(child, rec, new_edge_count);

	/* Surface this step's new-coverage signal to the chain executor
	 * (when called via run_sequence_chain). */
	if (found_new != NULL)
		*found_new = new_edges;

	/* CMP-bloom novelty is an equivalent corpus-save / mutator-win
	 * signal alongside PC-edge novelty.  Under a PC-edge plateau the
	 * PC-only gate fires for ~0% of calls; the OR-with-CMP gate keeps
	 * the corpus growing on arg neighbourhoods that exercise new
	 * compile-time-constant comparisons (the cmp_rising_pc_flat
	 * frontier).  PC-edge-specific bookkeeping below (frontier ring,
	 * snapshot cadence, per-strategy edge attribution, explorer/bandit
	 * pool edge counters) STAYS gated on new_edges -- those are
	 * PC-edge concepts by definition and contaminating them with
	 * CMP-source events would silently bias the bandit reward and
	 * corrupt the plateau diagnostics. */
	bool found_something = new_edges || (new_cmp > 0);

	account_warm_reserve(child, rec, new_edges, new_cmp, &pcres);

	/* If the win signal came from CMP novelty rather than PC novelty,
	 * tag the pending mutator attribution.  Tag-before-commit + the
	 * unconditional clear inside commit() together mean a stale tag
	 * from a !found_something path never leaks into the next call. */
	if (new_cmp > 0)
		minicorpus_mut_attrib_set_cmp_source();

	/* Credit each mutator case picked during this call's arg
	 * generation, with wins iff this call produced ANY novelty
	 * signal (PC-edge OR CMP-bloom).  PC-only credit was the matching
	 * half of the PC-only save gate; expanding both together keeps
	 * mutator productivity stats and corpus growth in lockstep. */
	minicorpus_mut_attrib_commit(found_something);

	/*
	 * SHADOW per-entry cmp-hint feedback scoring ([11-feedback-loop]
	 * PHASE 4).  Drain the per-child stash that cmp_hints_try_get_ex
	 * pushed onto during arg generation; credit per-entry pool wins/
	 * misses on the matching pool entries and bump the flat
	 * cmp_hint_wins / cmp_hint_misses / cmp_hint_cmp_novelty_wins
	 * counters.  Exactly ONE drain per parent dispatch:
	 *  - PC mode: credit_pc(true) on new_edges, credit_pc(false) on
	 *    no-edge.  PC-edge is the win signal the follow-up live-pick
	 *    weight will read.
	 *  - CMP mode with new_cmp > 0: credit_cmp_novelty (SEPARATE
	 *    counter; spec mandate -- CMP novelty must not masquerade as
	 *    PC-edge conversion).
	 *  - CMP mode with new_cmp == 0: just reset the stash, no credit
	 *    (PC-mode score is undefined for a CMP-mode call, and CMP
	 *    novelty did not fire).
	 *
	 * SHADOW: live pool selection in cmp_hints_try_get is uniform
	 * here -- only the per-entry scores and the flat counters record
	 * outcomes.  A future A/B-gated path will turn the scores into a
	 * weighted live pick.
	 *
	 * Gated on !child->in_reexec so the inner re-exec dispatch does
	 * not credit the outer parent's stash a second time.  The outer
	 * dispatch_step already credited and reset the stash above; the
	 * inner generate_syscall_args under in_reexec did not push (the
	 * stash helper gates on the same flag), so the inner stash is
	 * provably empty here.  Belt-and-braces vs an accidental future
	 * push that forgets the gate.
	 */
	if (!child->in_reexec) {
		/* Typed-hyp side channels: credit TRANSITION_WIN and
		 * CORPUS_SAVE on each hyp_injected stash entry BEFORE the
		 * PC / CMP-novelty drain below resets the stash.  Mirrors
		 * the same novelty conditions the parent dispatch uses:
		 * transition wins are credited when the kernel-side
		 * transition-edge counter advanced this call, and corpus
		 * saves are credited when this dispatch's args will land
		 * in the minicorpus (same gate the save block below
		 * checks).  Both credits are typed-hyp only -- the flat
		 * cmp_hint_* counters are unaffected. */
		if (pcres.transition_edges_real_local > 0)
			cmp_hints_feedback_credit_transition();
		if (unlikely(found_something) && entry->sanitise == NULL)
			cmp_hints_feedback_credit_corpus_save();

		if (child->kcov.mode == KCOV_MODE_PC) {
			cmp_hints_feedback_credit_pc(new_edges);
		} else if (new_cmp > 0) {
			cmp_hints_feedback_credit_cmp_novelty();
		} else {
			cmp_hints_feedback_reset_stash();
		}

		/* --blob-ab-mode: within-run A/B attribution.  When this
		 * call had a blob_fill() and the flag is on, blob_fill
		 * stashed the coin-flipped mode (HAVOC vs CMPDICT) on
		 * child->blob_ab_mode_last; credit one fill plus this
		 * call's novelty to that mode here: new_edges (PC),
		 * hit_cmp (per-call new_cmp>0 -- the verdict numerator on
		 * warm/PC-plateau runs where new_edges is ~0), and sum_cmp
		 * (CMP magnitude, non-gating shadow only).  Both arms
		 * share the same warm state / corpus / kcov context at
		 * every moment, so the per-fill rates are the clean
		 * per-mode comparison.  When the flag is absent the stamp
		 * stays BLOB_AB_MODE_NONE for every call and this block
		 * is inert. */
		if (child->blob_ab_mode_last == BLOB_AB_MODE_HAVOC) {
			__atomic_fetch_add(&shm->stats.blob_ab.havoc_fills,
					   1UL, __ATOMIC_RELAXED);
			if (new_edges > 0)
				__atomic_fetch_add(&shm->stats.blob_ab.havoc_new_edges,
						   (unsigned long) new_edges,
						   __ATOMIC_RELAXED);
			if (new_cmp > 0)
				__atomic_fetch_add(&shm->stats.blob_ab.havoc_hit_cmp,
						   1UL, __ATOMIC_RELAXED);
			__atomic_fetch_add(&shm->stats.blob_ab.havoc_sum_cmp,
					   new_cmp, __ATOMIC_RELAXED);
		} else if (child->blob_ab_mode_last == BLOB_AB_MODE_CMPDICT) {
			__atomic_fetch_add(&shm->stats.blob_ab.cmpdict_fills,
					   1UL, __ATOMIC_RELAXED);
			if (new_edges > 0)
				__atomic_fetch_add(&shm->stats.blob_ab.cmpdict_new_edges,
						   (unsigned long) new_edges,
						   __ATOMIC_RELAXED);
			if (new_cmp > 0)
				__atomic_fetch_add(&shm->stats.blob_ab.cmpdict_hit_cmp,
						   1UL, __ATOMIC_RELAXED);
			__atomic_fetch_add(&shm->stats.blob_ab.cmpdict_sum_cmp,
					   new_cmp, __ATOMIC_RELAXED);
		}
	}

	/* Save args that produced any novelty signal, but only for
	 * syscalls without sanitise (which may stash pointers).  Tag with
	 * the source so saves_by_reason[] separates PC-promoted from
	 * CMP-promoted entries; PC wins the tag on calls where both
	 * signals fire so the historical accounting is preserved. */
	if (unlikely(found_something)) {
		account_cold_overflow_would_save(entry, rec, new_cmp);

		if (entry->sanitise == NULL)
			minicorpus_save_with_reason(rec,
				new_edges ? CORPUS_SAVE_REASON_PC
					  : CORPUS_SAVE_REASON_CMP);
	}

	if (unlikely(new_edges))
		account_pc_edge_only(child, rec, new_edge_count,
				     rescue_cold_skip_pct_before);

	account_transition_reward(child, rec, &pcres);

	/* COMBINED-mode only: bump the per-syscall frontier-edge ring on
	 * the transition-discovery path so syscalls producing transitions
	 * (a new ordering through warm-known code) but no fresh PC bucket
	 * bits still earn frontier credit -- this is the whole point of
	 * promoting the signal, since the empirically-observed regime is
	 * one where transition discovery is healthy while PC-edge
	 * discovery has plateaued.  Under SHADOW_ONLY (the rollback path)
	 * the ring stays driven only by frontier_record_new_edge() so the
	 * silent-regime picker distribution remains byte-identical to the
	 * pre-knob baseline.  Same is_explorer + nr-bounds guards as the
	 * attribution block above. */
	if (pcres.transition_edges_real_local > 0 &&
	    !child->is_explorer && rec->nr < MAX_NR_SYSCALL &&
	    __atomic_load_n(&kcov_transition_reward_mode,
			    __ATOMIC_RELAXED) ==
	    KCOV_TRANSITION_REWARD_COMBINED)
		frontier_record_transition_edge((unsigned int)rec->nr);

	output_syscall_postfix(rec);

	handle_syscall_ret(rec, entry);

	/* Snapshot the completed call into the per-child ring so the parent
	 * has a chronological window of recent activity if a kernel taint
	 * fires before the next syscall. */
	child_syscall_ring_push(&child->syscall_ring, rec);

	/* Also append a compact record to the per-child pre-crash ring,
	 * dumped on __BUG() to attribute the assertion to a specific
	 * recent syscall.  rec->tp was just refreshed in do_syscall(). */
	pre_crash_ring_record(child, rec, &rec->tp);

	/* Single combined enqueue: op_count + success/failure +
	 * syscall_category_count[] all ride on one STATS_FIELD_CALL_COMPLETE
	 * slot.  The drain expands it back into three logical bumps.
	 * Result class is derived post-handle_syscall_ret(), which has
	 * already coerced rec->retval for retfd_rejected and is the
	 * canonical settle point for rec->state. */
	{
		enum stats_result_class result;

		if (__atomic_load_n(&rec->state, __ATOMIC_ACQUIRE) != AFTER)
			result = STATS_RESULT_INCOMPLETE;
		else if (rec->retval == (unsigned long)-1L)
			result = STATS_RESULT_FAILURE;
		else
			result = STATS_RESULT_SUCCESS;

		stats_ring_enqueue_call_complete(child->stats_ring,
						 (uint16_t)entry->syscall_category,
						 result);

		/* childop_split telemetry: attribute this syscall to the
		 * in-childop or random-syscall bucket based on the per-child
		 * flag set by child_process()'s per-op bracket.  Set when
		 * random_syscall() was reached from inside an alt-op op_fn
		 * (e.g. sched_cycler's inner loop), clear otherwise (direct
		 * CHILD_OP_SYSCALL fallthrough via run_sequence_chain).
		 * RELAXED add-fetch: cumulative diagnostic, lost-update races
		 * are tolerated.  Owner is the only writer of in_childop so
		 * no read race -- this child either is or isn't inside its
		 * own op_fn at this point. */
		if (child->in_childop) {
			__atomic_add_fetch(&shm->stats.syscall_dispatch.in_childops,
					   1UL, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.syscall_dispatch.random,
					   1UL, __ATOMIC_RELAXED);
		}
	}

	/* found_local_coverage feeds the F-RSEQ coverage watermark advance
	 * inside account_fd_and_group.  Local PC-edge novelty (new_edges)
	 * is the PC-mode signal; the LOCAL transition-edge count (pcres.
	 * transition_edges_real_local, populated by kcov_collect on the
	 * PC-mode side, zero-initialised on the CMP-mode side) is the
	 * transition-novelty signal.  Both are LOCAL by construction --
	 * remote-collected coverage is deliberately excluded so a pure
	 * observer that happened to harvest a remote edge is not falsely
	 * productive-marked.  The OR-of-both shape matches the design's
	 * watermark-advance contract (PC + local transition); each lane
	 * is independently sufficient. */
	{
		bool found_local_coverage = new_edges ||
			(pcres.transition_edges_real_local > 0);

		account_fd_and_group(child, entry, rec, found_local_coverage);
	}

	/* Per-arm completion exposure: bump the arm this call was attributed
	 * to.  Two distinct cases reach here with strategy_at_pick == -1:
	 *
	 *   - Explorer-pool children: set_syscall_nr() leaves the sentinel
	 *     in place and bumps strategy_picks[STRATEGY_RANDOM] directly.
	 *     The completion bump mirrors that pick by crediting RANDOM
	 *     here so picks and completions stay symmetric for the explorer
	 *     contribution.
	 *
	 *   - Replay steps from run_sequence_chain(): replay_syscall_step()
	 *     deliberately clears strategy_at_pick to -1 to avoid crediting
	 *     replay work to whichever arm started the chain.  Replays did
	 *     not bump strategy_picks[] either, so the completion bump must
	 *     skip them to keep picks and completions paired.
	 *
	 * Gate the fallback on child->is_explorer specifically rather than
	 * sap < 0 so the two cases stay separated.  Replay-step visibility
	 * lives in chain_corpus_shm->replay_steps_dispatched. */
	{
		int sap = child->strategy_at_pick;
		if (sap < 0 && child->is_explorer)
			sap = STRATEGY_RANDOM;
		if (sap >= 0 && sap < NR_STRATEGIES)
			__atomic_fetch_add(
				&shm->strategy_completed_calls[sap],
				1UL, __ATOMIC_RELAXED);
	}

	/*
	 * CMP RedQueen greedy re-exec tail.  Fires after the
	 * parent call's handle_syscall_ret has settled so .post / .cleanup
	 * are done before the re-exec dispatch reuses rec.  A single
	 * insertion point in dispatch_step so all callers
	 * (random_syscall_step, replay_syscall_step, sequence-chain step)
	 * inherit re-exec coverage automatically.
	 *
	 * Gates (ALL must pass):
	 *   - !in_reexec     -- recursion guard; otherwise we'd self-reinforce
	 *     a runaway loop.
	 *   - redqueen_enabled -- A/B-comparison stamp.
	 *   - kcov.mode == KCOV_MODE_CMP -- PC-mode children produce no
	 *     attribution.  Defensive: redqueen_enabled is only stamped
	 *     true on CMP-mode children today, but the gate keeps the
	 *     dispatch invariant local to this site.
	 *   - !in_chain_mid_step -- chains save their step sequence for
	 *     replay; a mid-chain re-exec is not part of that contract
	 *     and would double-count the step against the chain depth.
	 *   - new_cmp > 0 -- the parent must have produced at least one
	 *     bloom-novel CMP record.  A call that only re-harvested
	 *     known constants adds no information for re-exec.
	 *   - reexec_pending_count > 0 -- attribution scan in the parent's
	 *     cmp_hints_collect actually found a slot match.
	 *   - rate gate: ONE_IN(REDQUEEN_REEXEC_GATE_DENOM) baseline,
	 *     always-on while the plateau detector classifies the run as
	 *     CMP_RISING_PC_FLAT.  Combines low-cost steady-state lift
	 *     with full intensification under the diagnostic this re-exec
	 *     was designed to break.
	 */
	{
		/* Per-call gate disposition bucketing (PHASE 0 measurement-
		 * correctness): every dispatch_step that reaches this tail
		 * bumps EXACTLY ONE counter, partitioning the gap between
		 * reexec_attribution_found and reexec_attempts.  The
		 * evaluation order below mirrors the original short-circuited
		 * compound `if`; gate_skipped holds the counter address for
		 * the first failing gate (NULL == all gates cleared, the
		 * re-exec actually fired).  Behaviour is unchanged -- the
		 * reexec call site and rate-gate semantics are identical to
		 * the prior code; only the accounting around it is new. */
		unsigned long *gate_skipped = NULL;
		bool gate_passed = false;
		bool plateau_burst = false;

		if (child->in_reexec) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate.reexec_gate_skip_in_reexec
				: NULL;
		} else if (!child->redqueen_enabled) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate.reexec_gate_skip_disabled
				: NULL;
		} else if (child->kcov.mode != KCOV_MODE_CMP) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate.reexec_gate_skip_mode
				: NULL;
		} else if (child->in_chain_mid_step) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate.reexec_gate_skip_chain_mid
				: NULL;
		} else if (new_cmp == 0) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate.reexec_gate_skip_no_new_cmp
				: NULL;
		} else if (child->reexec_pending_count == 0) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate.reexec_gate_skip_no_pending
				: NULL;
		} else {
			/* All boolean gates cleared; the rate gate
			 * (ONE_IN(N) baseline plus always-on during a
			 * CMP_RISING_PC_FLAT plateau) decides between
			 * gate_pass and the rate-skip bucket. */
			if (kcov_shm != NULL &&
			    __atomic_load_n(&kcov_shm->plateau.plateau_active,
					    __ATOMIC_RELAXED)) {
				int h = __atomic_load_n(
					&shm->plateau_current_hypothesis,
					__ATOMIC_RELAXED);

				if (h == PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT)
					plateau_burst = true;
			}

			if (plateau_burst ||
			    ONE_IN(REDQUEEN_REEXEC_GATE_DENOM)) {
				/* Drain ALL staged reexec_pending entries
				 * for this parent dispatch (bounded by the
				 * producer-side MAX_REEXEC_PENDING cap).
				 * Each entry was independently
				 * attribution-scanned by cmp_hints_collect
				 * from the parent's CMP records, so each is
				 * an equally valid re-exec candidate; the
				 * prior single-drain rule discarded
				 * (count - 1) entries per dispatch even
				 * though every discarded entry had already
				 * cleared the parent's full outer-gate
				 * sequence (in_reexec, redqueen_enabled,
				 * kcov_mode, chain_mid, new_cmp, rate gate
				 * / plateau_burst).
				 *
				 * Per-entry safety is enforced inside
				 * redqueen_reexec_step (destructive-syscall
				 * denylist, validate_specific_syscall_silent,
				 * p->slot bounds, REDQUEEN_REEXEC_WINDOW_CAP);
				 * the window cap naturally bounds the
				 * per-window total attempts even when
				 * multiple drains fire per parent dispatch.
				 *
				 * in_reexec brackets the whole drain so each
				 * inner dispatch_step short-circuits at the
				 * outer in_reexec gate and cannot recurse
				 * into this drain.
				 *
				 * The --redqueen-pending-pick A/B flag is
				 * a no-op for this code path now (every
				 * staged entry is drained regardless of
				 * pick order); the per-pending-index
				 * success counters
				 * (kcov_shm->reexec_pending_hist.reexec_pending_pick_success[])
				 * still get bumped inside
				 * redqueen_reexec_step at the entry's true
				 * index, so per-slot/per-index lift remains
				 * directly readable.  MAX_REEXEC_PENDING
				 * clamp on the loop bound is defence in
				 * depth against a corrupted count reaching
				 * the array index.
				 *
				 * plateau_burst && burst_drain_arm_b:
				 * measure-arm burst-drain cap.  Arm B trims
				 * the drain to the first
				 * REDQUEEN_REEXEC_BURST_DRAIN entries and
				 * breaks the loop on a helper FAIL (the per-
				 * window ceiling hit, the destructive /
				 * validate-silent / bad-slot gates, or any
				 * future FAIL surface inside
				 * redqueen_reexec_step).  Arm A (control)
				 * keeps draining to MAX_REEXEC_PENDING with
				 * no early break so the two arms measure
				 * "surgical top-K drain during plateau" vs
				 * "greedy drain-all during plateau" on
				 * distinct-edge lift per attempt (see the
				 * per-arm counter block below the drain). */
				unsigned int count = child->reexec_pending_count;
				unsigned int i;
				bool burst_drain_arm =
					plateau_burst && child->burst_drain_arm_b;

				if (count > MAX_REEXEC_PENDING)
					count = MAX_REEXEC_PENDING;
				if (burst_drain_arm &&
				    count > REDQUEEN_REEXEC_BURST_DRAIN)
					count = REDQUEEN_REEXEC_BURST_DRAIN;

				child->in_reexec = true;
				for (i = 0; i < count; i++) {
					struct reexec_pending p =
						child->reexec_pending[i];
					bool fired;

					fired = redqueen_reexec_step(child, &p, i);
					if (burst_drain_arm && !fired)
						break;
				}
				child->in_reexec = false;
				gate_passed = true;
			} else {
				gate_skipped = (kcov_shm != NULL)
					? &kcov_shm->reexec_gate.reexec_gate_skip_rate
					: NULL;
			}
		}

		if (kcov_shm != NULL) {
			if (gate_passed)
				__atomic_fetch_add(
					&kcov_shm->reexec_gate.reexec_gate_pass,
					1UL, __ATOMIC_RELAXED);
			else if (gate_skipped != NULL)
				__atomic_fetch_add(gate_skipped,
						   1UL, __ATOMIC_RELAXED);
		}
	}

	/* Per-call attribution scratch is single-use: drained or not, the
	 * next call starts with a clean slate so a stale slot from the
	 * previous call cannot bleed into this call's attribution census. */
	child->reexec_pending_count = 0;

	/* Cheap end-of-call check for the strategy rotation boundary.
	 * Two relaxed loads + a compare in the common case; the CAS only
	 * fires once per ~STRATEGY_WINDOW ops fleet-wide. */
	maybe_rotate_strategy();

	if (new_cmp_out != NULL)
		*new_cmp_out = new_cmp;

	if (new_transition_out != NULL)
		*new_transition_out = pcres.transition_edges_real_local;

	return true;
}

bool random_syscall_step(struct childdata *child,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new,
			 unsigned long *new_transition_out,
			 unsigned long *new_cmp_out)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;

	if (set_syscall_nr(rec, child) == FAIL)
		return FAIL;

	rec->postbuffer[0] = '\0';

	/* Generate arguments, print them out */
	generate_syscall_args(rec);

	/* Sequence-chain substitution.  When the previous step in the chain
	 * returned a usable value, with CHAIN_SUBST_PCT probability splice
	 * it into one randomly-chosen arg slot of this call, overwriting
	 * whatever the generator produced.  Done after generate_syscall_args
	 * so the substituted value is what the kernel actually sees, and
	 * before output_syscall_prefix so the trace reflects the real call. */
	entry = get_syscall_entry(rec->nr, rec->do32bit);
	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);

	return dispatch_step(child, entry, found_new, new_cmp_out,
			     new_transition_out);
}

bool random_syscall(struct childdata *child)
{
	return random_syscall_step(child, false, 0, NULL, NULL, NULL);
}

/*
 * Fresh-args dispatch for a pre-picked syscall NR.  The chain executor
 * calls this when --chain-resource-typing=live has classified the
 * previous step as a resource producer and wants to steer the next
 * link to a random consumer of the same kind.  Skips set_syscall_nr()
 * (and its strategy attribution) exactly the way replay_syscall_step
 * does: any PC / CMP / transition novelty the biased step produces
 * gets credited to no arm, so the bandit reward signal is not
 * contaminated by an external NR override.
 *
 * Returns FAIL when the biased NR is no longer callable in this run
 * (out of range, no entry, sanitise, deactivated / AVOID / lost cap);
 * the chain executor then falls back to a plain random_syscall_step
 * for the same slot so the iteration still does useful work.
 */
bool random_syscall_step_biased(struct childdata *child,
				unsigned int bias_nr, bool bias_do32,
				bool have_substitute,
				unsigned long substitute_retval,
				bool *found_new,
				unsigned long *new_transition_out,
				unsigned long *new_cmp_out)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;

	if (bias_nr >= MAX_NR_SYSCALL)
		return FAIL;

	entry = get_syscall_entry(bias_nr, bias_do32);
	if (entry == NULL)
		return FAIL;

	/* Same sanitise gate replay_syscall_step uses: sanitise-bearing
	 * syscalls stash heap pointers into arg slots during
	 * generic_sanitise, and a fresh-args regeneration here would
	 * still route through generate_syscall_args -- but the bias
	 * consumer table is a static NR list, so a NR whose entry
	 * carries .sanitise cannot come out of pick_consumer(); the
	 * gate is defensive against a future table addition slipping a
	 * sanitise-tagged NR through unnoticed. */
	if (entry->sanitise != NULL)
		return FAIL;

	if (!validate_specific_syscall_silent(
			bias_do32 ? syscalls_32bit :
			(biarch ? syscalls_64bit : syscalls),
			(int)bias_nr))
		return FAIL;

	/* Bias dispatches never credit a bandit arm.  Same rationale as
	 * replay_syscall_step: the arm at shm->current_strategy did not
	 * actually pick this NR; letting its stamp ride through
	 * dispatch_step would leak reward attribution to whichever arm
	 * happens to be current at the time of the override. */
	child->strategy_at_pick = -1;
	child->frontier_pick_regime = FRONTIER_PICK_NONE;

	/* Publish (nr, do32bit) inside the srec bracket so an outside
	 * reader (watchdog, pre_crash_ring decode) cannot see the new
	 * (nr, do32bit) paired with the previous syscall's args.
	 * generate_syscall_args carries its own bracket for the a1..a6
	 * writes, and apply_chain_substitution writes through a1..a6
	 * again, so both come after this publish window closes. */
	srec_publish_begin(rec);
	rec->do32bit = bias_do32;
	rec->nr = bias_nr;
	srec_publish_end(rec);

	rec->postbuffer[0] = '\0';
	generate_syscall_args(rec);
	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);

	return dispatch_step(child, entry, found_new, new_cmp_out,
			     new_transition_out);
}

/*
 * Replay a saved chain step: stage the saved (nr, do32bit, args) into
 * rec, run the saved args through the per-arg mutator chain, apply any
 * Phase 1 retval substitution from the prior step, and dispatch through
 * the same path random_syscall_step uses.  Returns FAIL when the saved
 * syscall is no longer callable in this run (deactivated, AVOID_SYSCALL,
 * needs root we don't have, or has a sanitise that would stash stale
 * pointers); the chain executor falls back to fresh args in that case.
 *
 * The mutator call goes to minicorpus_mutate_args, which is the same
 * splice + weighted-stack-mutate engine the per-syscall mini-corpus
 * replay uses.  Sharing the mutator means chain replay automatically
 * inherits productivity tuning from the existing weighted scheduler
 * rather than duplicating the mutation logic with its own counters.
 */
bool replay_syscall_step(struct childdata *child,
			 const struct chain_step *saved,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new,
			 unsigned long *new_transition_out,
			 unsigned long *new_cmp_out)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;
	unsigned long args[6];

	if (saved->nr >= MAX_NR_SYSCALL)
		return FAIL;

	entry = get_syscall_entry(saved->nr, saved->do32bit);
	if (entry == NULL)
		return FAIL;

	/* sanitise-bearing syscalls allocate and stash heap pointers into
	 * arg slots during generic_sanitise; replay would feed stale args
	 * to those slots.  Same gate the mini-corpus uses for the same
	 * reason. */
	if (entry->sanitise != NULL)
		return FAIL;

	/* The syscall may have been deactivated since the chain was saved
	 * (returned ENOSYS, hit AVOID_SYSCALL, lost a CAP_*).  Bail out
	 * rather than replay an inert call. */
	if (!validate_specific_syscall_silent(
			saved->do32bit ? syscalls_32bit :
			(biarch ? syscalls_64bit : syscalls),
			(int)saved->nr))
		return FAIL;

	memcpy(args, saved->args, sizeof(args));
	minicorpus_mutate_args(args, entry, saved->nr);

	/* Replay steps bypass set_syscall_nr() (which is where the bandit's
	 * per-arm pick stamp normally lands), so the child still holds the
	 * strategy_at_pick value from whichever fresh pick started the
	 * chain.  Letting that stale stamp ride through dispatch_step would
	 * credit replay-step PC/CMP novelty -- and the per-arm completion
	 * bump -- to an arm that did not actually pick the replayed syscall,
	 * contaminating the reward signal the bandit is meant to learn
	 * from.  Reset to the -1 sentinel so the existing strategy_at_pick
	 * gates at the consumer sites (kcov_collect_cmp / bandit_cmp_observe,
	 * the PC-edge per-strategy attribution in dispatch_step, the per-arm
	 * completion bump) all skip attribution for this step.
	 *
	 * The next fresh set_syscall_nr() overwrites strategy_at_pick
	 * unconditionally on the bandit-pool path, so leaving -1 here does
	 * not leak into subsequent non-replay calls. */
	child->strategy_at_pick = -1;

	if (chain_corpus_shm != NULL)
		__atomic_fetch_add(&chain_corpus_shm->replay_steps_dispatched,
				   1UL, __ATOMIC_RELAXED);

	/* Publish the (nr, do32bit) advance, the arg writes, the
	 * postbuffer reset, and the chain substitution as one coherent
	 * step.  An outside reader (watchdog thread, parent inspecting
	 * via shm, pre_crash_ring decode) that samples rec mid-step must
	 * not see the new (nr, do32bit) paired with the previous
	 * syscall's a1..a6 — that torn pairing miscredits args to the
	 * wrong syscall in divergence stats and crash-ring reconstruction.
	 * apply_chain_substitution writes rec->aN, so the publish_end
	 * has to come after it. */
	srec_publish_begin(rec);
	rec->do32bit = saved->do32bit;
	rec->nr = saved->nr;

	rec->a1 = args[0];
	rec->a2 = args[1];
	rec->a3 = args[2];
	rec->a4 = args[3];
	rec->a5 = args[4];
	rec->a6 = args[5];

	rec->postbuffer[0] = '\0';

	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);
	srec_publish_end(rec);

	return dispatch_step(child, entry, found_new, new_cmp_out,
			     new_transition_out);
}

/*
 * Pin a single arg slot to a learned-constant value.  Slot is 1-based
 * (matches the rec->aN naming and reexec_pending::slot encoding); size is
 * the kernel comparison width in bytes and drives the width-preserving
 * splice below.  Out-of-range slots are dropped silently -- the caller
 * validated against the entry's num_args at attribution emit time, but
 * defensive against a corrupted pending entry that survived the slot
 * bound check.
 */
static void redqueen_pin_slot(struct syscallrecord *rec, unsigned int slot,
			      unsigned long value, unsigned int size)
{
	unsigned long *aN;
	unsigned long m;

	switch (slot) {
	case 1: aN = &rec->a1; break;
	case 2: aN = &rec->a2; break;
	case 3: aN = &rec->a3; break;
	case 4: aN = &rec->a4; break;
	case 5: aN = &rec->a5; break;
	case 6: aN = &rec->a6; break;
	default: return;
	}

	/*
	 * A narrow compare (0 < size < sizeof(long)) examined only the low
	 * size*8 bits, so keep the freshly regenerated arg's high bits and
	 * splice in just the constant's low bytes -- overwriting the whole
	 * slot with a narrow constant zeroes load-bearing high bits (pointer
	 * / packed field / flags) and the arg goes invalid before the kernel
	 * reaches the compare.  Full / unknown width (>= sizeof(long) or 0)
	 * masks to ~0 == plain overwrite.
	 */
	m = (size > 0 && size < sizeof(unsigned long))
		? ((1UL << (size * 8U)) - 1UL) : ~0UL;
	*aN = (*aN & ~m) | (value & m);
}

/*
 * Field-scoped pin ([11-field-scoped]).  Unlike redqueen_pin_slot, the
 * targeted slot holds a POINTER to a freshly-regenerated fixed-size
 * struct; pin a single field inside that buffer and leave the rest of
 * the generated struct intact, so a kernel comparison that fired on one
 * field is satisfied without clobbering the whole arg.  Slot is 1-based.
 *
 * The buffer pointer is read AFTER generate_syscall_args() has run, so
 * it is whatever the generator just produced -- which for ARG_TIMESPEC
 * is either a valid pool pointer or the generator's ~10% NULL arm.  A
 * NULL / implausibly small pointer is left unpinned (the re-exec still
 * runs with fresh args, just without the field pin); the per-window cap
 * bounds the wasted budget.  Only the ARG_TIMESPEC tv_sec/tv_nsec pair
 * is wired today.
 */
static void redqueen_pin_field(struct syscallrecord *rec,
			       const struct reexec_pending *p)
{
	unsigned long ptr;
	struct timespec *ts;

	switch (p->slot) {
	case 1: ptr = rec->a1; break;
	case 2: ptr = rec->a2; break;
	case 3: ptr = rec->a3; break;
	case 4: ptr = rec->a4; break;
	case 5: ptr = rec->a5; break;
	case 6: ptr = rec->a6; break;
	default: return;
	}

	if (ptr < 4096)
		return;

	switch (p->field_kind) {
	case REEXEC_FIELD_TIMESPEC_SEC:
		ts = (struct timespec *) ptr;
		ts->tv_sec = (time_t) p->value;
		break;
	case REEXEC_FIELD_TIMESPEC_NSEC:
		ts = (struct timespec *) ptr;
		ts->tv_nsec = (long) p->value;
		break;
	case REEXEC_FIELD_NONE:
	default:
		break;
	}
}

/*
 * Greedy CMP RedQueen re-exec step.  Mirrors replay_syscall_step's
 * contract: resolve the entry, gate on sanitise-free (heap-pointer-
 * laundering inside generic_sanitise would either resurrect freed
 * slots or stomp the pin), gate on AVOID_REEXEC (auditable opt-out
 * for sanitise-free destructive entries -- see include/syscall.h),
 * gate on validate_specific_syscall_silent (caller may have lost a
 * cap / hit AVOID_SYSCALL / been deactivated since dispatch).  Then
 * regenerate fresh args via generate_syscall_args, overwrite the
 * targeted slot with the captured kernel-side constant, and re-enter
 * dispatch_step for the actual call.  Rec state is snapshotted on
 * entry and restored on exit so the chain-corpus save in sequence.c
 * (which reads rec->a1..a6 after dispatch_step returns) sees the
 * ORIGINAL dispatched args, not the re-exec's args.
 *
 * Per-call cap is enforced at the dispatch_step tail (C-1: 1 re-exec
 * per parent); per-window cap is enforced here so a corrupted /
 * misbehaving caller can't bypass it by calling the helper directly.
 */
static bool redqueen_reexec_step(struct childdata *child,
				 const struct reexec_pending *p,
				 unsigned int pending_idx)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;
	unsigned long saved_a[6];
	unsigned long saved_retval, saved_post_state;
	int saved_errno_post;
	bool ok;

	/* Per-window cap.  Reset to a fresh window
	 * once REDQUEEN_REEXEC_WINDOW_OPS child iterations have elapsed
	 * since the last reset; cap exceedance within a window short-
	 * circuits before any of the more expensive entry resolution. */
	if (child->op_nr - child->reexec_window_start_op >=
	    REDQUEEN_REEXEC_WINDOW_OPS) {
		child->reexec_window_start_op = child->op_nr;
		child->reexec_count_window = 0;
	}
	if (child->reexec_count_window >= REDQUEEN_REEXEC_WINDOW_CAP) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_flat.reexec_window_cap_hit,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	entry = get_syscall_entry(rec->nr, rec->do32bit);
	if (entry == NULL) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_step_skip_entry_null,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	/* Destructive-syscall gate: sanitise-bearing entries replay would
	 * either re-allocate (and leak) heap state for slots whose previous
	 * sanitise has already been freed by .cleanup, or stomp the captured
	 * pin with the re-sanitise's preferred value.  Same gate
	 * replay_syscall_step uses for the same reason.  Layered with the
	 * AVOID_REEXEC denylist for sanitise-free entries whose effects are
	 * still destructive to the calling child or to global state. */
	if ((entry->sanitise != NULL && !(entry->flags & REEXEC_SANITISE_OK)) ||
	    (entry->flags & AVOID_REEXEC)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_flat.reexec_skipped_destructive,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (!validate_specific_syscall_silent(
			rec->do32bit ? syscalls_32bit :
			(biarch ? syscalls_64bit : syscalls),
			(int)rec->nr)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_flat.reexec_skipped_validate_silent,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (p->slot == 0 || p->slot > entry->num_args) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_step_skip_bad_slot,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	/* Snapshot the rec fields the re-exec's dispatch_step will rewrite.
	 * Restore on exit so a caller that reads rec after the helper
	 * returns -- the chain-corpus save in sequence.c being the
	 * load-bearing one -- sees the original dispatched call's args /
	 * retval, not the re-exec's.  nr / do32bit are NOT in the snapshot
	 * set: redqueen always dispatches the same (nr, do32) as the
	 * parent, so those fields stay invariant across the helper. */
	saved_a[0] = rec->a1;
	saved_a[1] = rec->a2;
	saved_a[2] = rec->a3;
	saved_a[3] = rec->a4;
	saved_a[4] = rec->a5;
	saved_a[5] = rec->a6;
	saved_retval = rec->retval;
	saved_post_state = rec->post_state;
	saved_errno_post = rec->errno_post;

	/* Coherent re-publishes around the re-exec dispatch state.  Same
	 * (nr, do32bit) as the parent so those don't need re-publication,
	 * but three other rec mutations do, and each runs in its own
	 * publish bracket (generate_syscall_args carries its own bracket
	 * internally, so it can't be folded into either neighbour):
	 *   1. postbuffer reset (this bracket) -- a pre_crash decoder
	 *      sampling between dispatches must not pair stale postbuffer
	 *      bytes with the new in-flight call.
	 *   2. fresh args, published by generate_syscall_args's own bracket.
	 *   3. the slot / field pin (bracket below) -- generate_syscall_args
	 *      has already closed its publish_end by the time the pin runs,
	 *      so the pin would otherwise land OUTSIDE any publish section
	 *      and an out-of-band reader (parent watchdog, pre_crash
	 *      decoder) could observe the pinned slot torn against the
	 *      generator's freshly-published aN values. */
	srec_publish_begin(rec);
	rec->postbuffer[0] = '\0';
	srec_publish_end(rec);

	generate_syscall_args(rec);

	srec_publish_begin(rec);
	if (p->field_kind == REEXEC_FIELD_NONE)
		redqueen_pin_slot(rec, p->slot, p->value, p->size);
	else
		redqueen_pin_field(rec, p);
	srec_publish_end(rec);

	/* Don't credit the bandit for re-exec wins -- same rationale as
	 * replay_syscall_step.  -1 sentinel makes the per-strategy
	 * attribution and per-arm completion sites skip this dispatch. */
	child->strategy_at_pick = -1;

	if (kcov_shm != NULL) {
		unsigned int op_type = (unsigned int)child->op_type;

		__atomic_fetch_add(&kcov_shm->reexec_flat.reexec_attempts, 1UL,
				   __ATOMIC_RELAXED);
		/* per-nr partition of the re-exec attempt
		 * counter.  Reaching this site means the destructive /
		 * validate_silent / slot-bounds gates above already cleared,
		 * so the bump is attributed to the same syscall that the
		 * inner dispatch_step will actually re-run. */
		if (rec->nr < MAX_NR_SYSCALL)
			__atomic_fetch_add(
				&kcov_shm->reexec_pending_hist.reexec_attempts_by_syscall[rec->nr],
				1UL, __ATOMIC_RELAXED);
		/* per-childop partition of the re-exec attempt counter,
		 * sibling of the per-syscall bump above.  Lets a re-exec
		 * driven by a non-OP_SYSCALL childop (recipe runner, io_uring
		 * flood, etc.) be counted separately from the same nr fired
		 * from the default OP_SYSCALL flow. */
		if (op_type < KCOV_CHILDOP_NR_MAX)
			__atomic_fetch_add(
				&kcov_shm->reexec_gate.reexec_attempts_by_childop[op_type],
				1UL, __ATOMIC_RELAXED);
	}
	child->reexec_count_window++;

	{
		unsigned long inner_new_cmp = 0;
		unsigned long inner_new_edges = 0;

		/* The re-exec's lift signal is the inner dispatch's per-call
		 * bloom-novel CMP count -- the authoritative value
		 * kcov_collect_cmp() returns to dispatch_step's local new_cmp.
		 * Surfacing it via the out-param avoids sampling the shared
		 * cmp_records_collected counter around the call: those relaxed
		 * loads race other CMP children's increments (over-attributing
		 * their records to this re-exec) and count raw duplicate
		 * records (not just novel ones), the same bug class avoided
		 * for PC edges via kcov_collect()'s new_edge_count out-param.
		 *
		 * The 6th param (inner_new_edges) reports the inner call's
		 * pcres.transition_edges_real_local; distinct transition-edge
		 * lift is the go/no-go metric for the plateau_burst measure
		 * arm (§4 of the plateau-burst spec) because a fresh CMP
		 * record that opens no new distinct edge is invisible to the
		 * 85k distinct-PC-edge wall the intensification is meant to
		 * break. */
		ok = dispatch_step(child, entry, NULL, &inner_new_cmp,
				   &inner_new_edges);

		if (kcov_shm != NULL) {
			unsigned int arm = child->burst_drain_arm_b ? 1U : 0U;

			/* Per-arm attempt denominator for the plateau_burst
			 * A/B measure.  Bumped on every attempt regardless of
			 * inner_new_cmp so the per-arm ratio
			 *   reexec_new_edges_by_arm[arm] /
			 *   reexec_attempts_by_arm[arm]
			 * has a clean denominator on both cohorts. */
			__atomic_fetch_add(&kcov_shm->reexec_attempts_by_arm[arm],
					   1UL, __ATOMIC_RELAXED);

			/* Per-arm distinct-edge lift for the plateau_burst
			 * A/B measure.  Bumped unconditionally by the inner
			 * transition-edge delta (0 attempts contribute 0 --
			 * cheaper than a branch that skips the add). */
			__atomic_fetch_add(&kcov_shm->reexec_new_edges_by_arm[arm],
					   inner_new_edges, __ATOMIC_RELAXED);
			__atomic_fetch_add(&kcov_shm->reexec_new_edges_total,
					   inner_new_edges, __ATOMIC_RELAXED);
		}

		if (kcov_shm != NULL && inner_new_cmp > 0) {
			unsigned int op_type = (unsigned int)child->op_type;
			unsigned int arm = child->burst_drain_arm_b ? 1U : 0U;

			/* Discrete count of attempts that produced novelty
			 * (PHASE 0 measurement).  Sibling of reexec_attempts
			 * (the denominator) and reexec_new_cmps_total (the
			 * SUM of inner_new_cmp).  The existing sum / attempts
			 * pair conflates hit-rate with mean-novelty-per-win;
			 * this discrete bump splits them. */
			__atomic_fetch_add(&kcov_shm->reexec_flat.reexec_attempts_with_new_cmp,
					   1UL, __ATOMIC_RELAXED);
			__atomic_fetch_add(&kcov_shm->reexec_flat.reexec_new_cmps_total,
					   inner_new_cmp, __ATOMIC_RELAXED);
			/* Per-arm CMP-novelty lift for the plateau_burst A/B
			 * measure: sibling of reexec_new_edges_by_arm above so
			 * a run can compare arm ratios on either the edge-lift
			 * (primary) or the CMP-novelty (secondary) axis. */
			__atomic_fetch_add(&kcov_shm->reexec_new_cmps_by_arm[arm],
					   inner_new_cmp, __ATOMIC_RELAXED);
			if (rec->nr < MAX_NR_SYSCALL)
				__atomic_fetch_add(
					&kcov_shm->reexec_flat.per_syscall_cmp_novelty_reexec[rec->nr],
					inner_new_cmp, __ATOMIC_RELAXED);
			/* per-childop partition of the re-exec lift signal,
			 * sibling of the per-syscall sibling above.  Same
			 * inner_new_cmp accumulation; the childop dimension
			 * answers "which non-OP_SYSCALL childops are
			 * harvesting the bulk of the re-exec CMP novelty". */
			if (op_type < KCOV_CHILDOP_NR_MAX)
				__atomic_fetch_add(
					&kcov_shm->reexec_gate.per_childop_cmp_novelty_reexec[op_type],
					inner_new_cmp, __ATOMIC_RELAXED);
			/* per-slot success counter.  Pair
			 * with reexec_attribution_slot_hist (the per-slot
			 * attempt-attribution histogram) to read per-slot
			 * success rate -- a slot that attracts the bulk of
			 * attributions but produces no novelty wins is
			 * wasted re-exec budget.  p->slot is 1-based and
			 * was bounds-checked at the consumer-side
			 * (p->slot <= entry->num_args) gate above. */
			if (p->slot >= 1 &&
			    p->slot <= CMP_REDQUEEN_SLOT_HIST_NR)
				__atomic_fetch_add(
					&kcov_shm->reexec_pending_hist.reexec_success_by_slot[p->slot - 1],
					1UL, __ATOMIC_RELAXED);
			/* Per-pending-buffer-index success counter, the
			 * A/B signal for --redqueen-pending-pick.  The
			 * caller's pick site clamps pending_idx to
			 * [0, child->reexec_pending_count) and the
			 * reexec_pending_count==0 short-circuit one level
			 * above guarantees count > 0 there, so a sane
			 * caller always lands in range -- the explicit
			 * REEXEC_PENDING_PICK_HIST_NR clamp here is
			 * defence in depth against a future caller
			 * passing an out-of-range index (or a corrupted
			 * reexec_pending_count value reaching
			 * rnd_modulo_u32 and rolling past the bound). */
			if (pending_idx < REEXEC_PENDING_PICK_HIST_NR)
				__atomic_fetch_add(
					&kcov_shm->reexec_pending_hist.reexec_pending_pick_success[pending_idx],
					1UL, __ATOMIC_RELAXED);
		}
	}

	/* Restore the dispatched-call state so downstream readers (the
	 * chain-corpus save in particular) see the parent's args / retval,
	 * not the re-exec's.  Wrap in a publish bracket so a watchdog
	 * sampling rec mid-restore does not catch the rec halfway between
	 * the re-exec values and the parent values. */
	srec_publish_begin(rec);
	rec->a1 = saved_a[0];
	rec->a2 = saved_a[1];
	rec->a3 = saved_a[2];
	rec->a4 = saved_a[3];
	rec->a5 = saved_a[4];
	rec->a6 = saved_a[5];
	rec->retval = saved_retval;
	rec->post_state = saved_post_state;
	rec->errno_post = saved_errno_post;
	srec_publish_end(rec);

	return ok;
}
