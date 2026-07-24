/*
 * handle_syscall_ret coordinator and its three phase helpers, carved
 * out of dispatch/syscall.c.  Ordering across the phases is preserved
 * exactly: validate -> dispatch -> post.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "argtype-ops.h"
#include "child.h"
#include "cred_throttle.h"
#include "deferred-free.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pre_crash_ring.h"
#include "prop_ring.h"
#include "results.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "syscall-internal.h"
#include "syscall_record.h"
#include "tables.h"
#include "uid.h"
#include "utils.h"

/*
 * Rate-limited (at most once per second per child) WARNING for canary
 * mismatches.  A wholesale stomp from a sibling syscall can land on
 * many recs in quick succession; without throttling the log floods.
 * Per-process static is fine — one storm from one child is interesting,
 * the second sample from the same child within a second adds nothing.
 */
static void canary_stomp_warn_ratelimited(const struct syscallentry *entry,
					  uint64_t observed)
{
	static struct timespec last_warn;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (now.tv_sec == last_warn.tv_sec)
		return;
	last_warn = now;

	outputerr("WARNING: rec canary stomped during %s: observed=0x%lx (expected 0x%lx) -- syscallrecord wholesale-clobbered between BEFORE and AFTER\n",
		  entry->name, (unsigned long) observed,
		  (unsigned long) REC_CANARY_MAGIC);
}

/* Phase 1 of handle_syscall_ret: pre-dispatch validation gates.
 * Runs the wholesale rec-canary stomp check, the RET_ZERO_SUCCESS
 * retval-contract bound, and the RET_FD shape rejection.  Reports
 * the two rejection flags via out-params so the post phase can gate
 * entry->post and the ret_objtype_via_post registrar on them. */
static void syscall_ret_validate_phase(struct syscallrecord *rec,
				       struct syscallentry *entry,
				       bool *retfd_rejected,
				       bool *rzs_rejected)
{
	/* Wholesale-stomp check: if anything overwrote the rec while the
	 * kernel had control, the canary won't match.  Catches the rarer
	 * class the per-arg snapshot pattern can't shadow (bookkeeping
	 * fields, the whole struct alias-clobbered by a sibling
	 * value-result write).  Informational — the call has already
	 * returned and downstream guards (post_handler_corrupt_ptr, the
	 * snapshots, deferred_free's pid-shape filter) still cover the
	 * pointer-deref hazards individually; we're just here to surface
	 * that the wholesale class is firing. */
	{
		uint64_t observed = rec->_canary;

		if (unlikely(observed != REC_CANARY_MAGIC)) {
			__atomic_add_fetch(&shm->stats.diag.rec_canary_stomped, 1,
					   __ATOMIC_RELAXED);
			pre_crash_ring_record_canary(this_child(), rec, observed);
			canary_stomp_warn_ratelimited(entry, observed);
			/* Restamp so a second post-handler invocation on the
			 * same rec (none today, but cheap insurance) doesn't
			 * re-fire on the stale mismatch. */
			rec->_canary = REC_CANARY_MAGIC;
		}
	}

	/* Writer-pinning canary, Stage 1 detector (--writer-pin-sweep).
	 *
	 * DEFAULT OFF.  When enabled, sweep the shared minicorpus rings for
	 * a stomped wp_canary or a count>32 invariant violation, fire ONCE
	 * per child on the first hit, and emit a single SUSPECT line that
	 * names the observer context (this child / this syscall) plus the
	 * stomped address.  The address is the deliverable: feed it to a
	 * subsequent run's --writer-watch=<addr> to synchronously name the
	 * wild writer via the Stage-2 HW breakpoint.
	 *
	 * Do NOT interpret the observer context as proof of who scribbled
	 * the canary: the sweep is async polling, so a sibling child writing
	 * via a value-result syscall might land the scribble while THIS
	 * child sweeps -- the observer/victim is not the writer.  That is
	 * exactly the reason Stage 2 exists; the sweep just hands off an
	 * address. */
	if (unlikely(writer_pin_sweep && minicorpus_shm != NULL)) {
		static unsigned int wp_tick;
		static bool wp_fired;
		unsigned int n;

		n = __atomic_add_fetch(&wp_tick, 1, __ATOMIC_RELAXED);
		if (!wp_fired &&
		    (writer_pin_stride <= 1 || (n % writer_pin_stride) == 0)) {
			unsigned long bad_addr = 0;
			uint64_t bad_val = 0;

			if (minicorpus_wp_sweep(&bad_addr, &bad_val)) {
				wp_fired = true;
				outputerr("WRITER-PIN-SWEEP SUSPECT: minicorpus canary stomped"
					  " bad_addr=0x%lx bad_val=0x%lx"
					  " observer_syscall=%s observer_nr=%u observer_pid=%d"
					  " -- feed bad_addr to --writer-watch=0x%lx"
					  " to NAME the wild writer (sweep observer != writer)\n",
					  bad_addr, (unsigned long)bad_val,
					  entry->name, rec->nr, getpid(), bad_addr);
			}
		}
	}

	/* Blanket bound for RET_ZERO_SUCCESS handlers.  The contract for
	 * this rettype is rec->retval ∈ {0, -1UL} -- success returns 0,
	 * failure returns -1 with errno set.  Anything else means the
	 * retval slot was scribbled between the syscall return and our
	 * load (a torn upper-bit write, or a sibling value-result syscall
	 * whose buffer aliased rec->retval without disturbing the canary).
	 * One gate at the dispatcher chokepoint covers every handler
	 * advertising RET_ZERO_SUCCESS -- whether the rettype is set
	 * statically in the syscallentry or overridden per-cmd by a
	 * sanitise hook (fcntl, futex) -- so we don't have to sprinkle
	 * the same retval bound across the ~85 .post handlers individually.
	 * Rettype is sourced via effective_rettype(): static-contract entries
	 * are read from the immutable entry, op-multiplexed entries from the
	 * sanitise-published rec.  rzs_blanket_reject is the headline counter
	 * for this class: a dispatcher-level rettype-contract violation
	 * (a sibling scribbled rec->retval after the syscall returned),
	 * counted separately from a .post handler rejecting a pid-shaped
	 * pointer in rec->aN under post_handler_corrupt_ptr, so the headline
	 * counter is accurate and per-handler attribution stays clean.
	 *
	 * Coerce the impossible retval to -1UL / EINVAL and set
	 * rzs_rejected so downstream handlers cannot act on the
	 * fabricated value.  Without coercion the success branch below
	 * runs for any rec->retval != -1UL, and a RET_ZERO_SUCCESS
	 * .ret_objtype_via_post handler (timer_create) then treats the
	 * stomped scalar as a successful return and publishes a bogus
	 * timer id into the OBJ_TIMERID pool -- a later timer_delete()
	 * picks up the garbage and faults inside glibc's per-process
	 * timer table.  Mirrors reject_corrupt_retfd's coerce-to-failure
	 * shape so the failure branch handles it identically to a real
	 * EINVAL.  handle_success(), register_returned_fd() and
	 * prop_ring_push() all short-circuit on retval == -1UL already,
	 * so the coercion alone suppresses those paths; rzs_rejected
	 * gates only the post-derived registrar and entry->post (defence
	 * in depth, matching the retfd_rejected pattern at the same
	 * site). */
	if (unlikely(effective_rettype(entry, rec) == RET_ZERO_SUCCESS &&
		     rec->retval != 0 && rec->retval != -1UL)) {
		__atomic_add_fetch(&shm->stats.diag.rzs_blanket_reject, 1,
				   __ATOMIC_RELAXED);
		outputerr("rzs: rejecting out-of-bound retval=0x%lx for %s\n",
			  rec->retval, entry->name);
		rec->retval = (unsigned long)-1L;
		rec->errno_post = EINVAL;
		*rzs_rejected = true;
	}

	/* Validate RET_FD shape before success/failure dispatch.  A
	 * structurally corrupt fd return (e.g. upper bits set, or below the
	 * NR_OPEN ceiling but negative-when-cast) is != -1UL, so without
	 * this gate it would take the success branch: handle_success()
	 * scoreboards the bogus value, entry->successes and stats.successes
	 * both bump.  Coercing to -1UL here lets the dispatch below route
	 * the rejected case through handle_failure() naturally, and the
	 * forced errno_post = EINVAL drops cleanly into the errno bucket.
	 *
	 * Capture the rejection so we can both (a) tally it under a
	 * dedicated counter -- the failures aggregate folds this with
	 * legitimate -1UL returns and would drown the corruption signal
	 * in the noise of normal failed syscalls -- and (b) skip
	 * entry->post() on the corrupt path so a .post handler that
	 * happens not to short-circuit on (long)retval < 0 (defence in
	 * depth: every RET_FD .post in-tree does, but the dispatcher
	 * shouldn't have to trust that going forward) can't act on a
	 * fabricated return.  Sub-attribution by (nr, do32bit) was
	 * already routed to post_handler_corrupt_ptr_bump's per-handler
	 * ring from inside reject_corrupt_retfd(), so this counter is
	 * the headline tally and the per-handler ring carries the
	 * per-syscall breakdown. */
	*retfd_rejected = reject_corrupt_retfd(entry, rec);
	if (*retfd_rejected)
		__atomic_add_fetch(&shm->stats.diag.retfd_blanket_reject, 1,
				   __ATOMIC_RELAXED);
}

/* Phase 2 of handle_syscall_ret: success/failure result dispatch.
 * Both branches gate on state == AFTER -- an EXTRA_FORK grandchild
 * may die / get SIGKILL'd before publishing AFTER, in which case
 * rec->retval and rec->errno_post are stale shm noise.  Failure
 * branch handles ENOSYS deactivation, handle_failure(), and the
 * per-errno classification; success branch routes through
 * handle_success() + entry->successes. */
static void syscall_ret_dispatch_phase(struct syscallrecord *rec,
				       struct syscallentry *entry,
				       unsigned int call)
{
	if (rec->retval == -1UL) {
		int err = rec->errno_post;

		/* For EXTRA_FORK syscalls (e.g. execve), the grandchild runs
		 * with state GOING_AWAY and may die or get killed before
		 * setting state to AFTER.  Only process the result if the
		 * syscall actually completed. */
		if (__atomic_load_n(&rec->state, __ATOMIC_ACQUIRE) == AFTER) {
			/* dry-run synthesizes ENOSYS for every un-executed
			 * syscall; skip deactivation so the table isn't drained. */
			if (err == ENOSYS && !dry_run)
				deactivate_enosys(rec, entry, call);

			handle_failure(rec);
			__atomic_add_fetch(&entry->failures, 1, __ATOMIC_RELAXED);
			if (err >= 0 && err <= NR_ERRNOS) {
				__atomic_add_fetch(&entry->errnos[err], 1, __ATOMIC_RELAXED);
			} else if (err < 0) {
				/* A real kernel return can never produce a
				 * negative errno_post: __do_syscall stores
				 * errno (always >= 0) into rec->errno_post
				 * before publishing state = AFTER.  The only
				 * way err lands here is a sibling child
				 * stomping on this rec in shared memory after
				 * AFTER was published -- leaving retval = -1UL
				 * and state = AFTER intact but trampling
				 * errno_post with garbage.  Without a lower
				 * bound the original guard (err < NR_ERRNOS,
				 * signed) admits negative values and indexes
				 * entry->errnos[] before the array, silently
				 * corrupting whatever struct field precedes
				 * the errnos[] member in the per-syscall
				 * entry.  Log with a distinct message so this
				 * corruption shape can be told apart in
				 * post-mortem logs from the err >= NR_ERRNOS
				 * shape handled below. */
				outputerr("negative errno_post after doing %s: %d (sibling stomp on shared syscallrecord?)\n",
					entry->name, err);
			} else {
				// "These should never be seen by user programs."
				// But trinity isn't a 'normal' user program, we're doing
				// stuff that libc hides from apps.
				if (err < 512 || err > 530)
					outputerr("errno out of range after doing %s: %d:%s\n",
						entry->name,
						err, strerror(err));
			}
		}
	} else if (__atomic_load_n(&rec->state, __ATOMIC_ACQUIRE) == AFTER) {
		/* Symmetric guard to the failure branch above: an
		 * EXTRA_FORK grandchild that was SIGKILL'd by
		 * do_extrafork's 1-second timeout (or died in execve)
		 * before reaching __do_syscall's AFTER block leaves
		 * rec->retval as whatever the previous syscall stamped
		 * into shm.  Without this gate handle_success() would
		 * scoreboard a stale fd/len, and entry->successes /
		 * the successes aggregate would tally a syscall that
		 * never actually returned. */
		handle_success(rec);	// Believe me folks, you'll never get bored with winning
		__atomic_add_fetch(&entry->successes, 1, __ATOMIC_RELAXED);
	}
}

/* Map (retval, errno) into the 3-class errno gradient consumed by the
 * shadow gradient hook below.  See the errno_gradient_* block in
 * include/stats.h for the class definitions and the SHADOW contract.
 * Caller has already gated on state == AFTER, so rec->retval /
 * rec->errno_post are the real post-call values, not the previous
 * syscall's stale shm noise. */
static inline unsigned int errno_gradient_class(unsigned long retval,
						int err)
{
	if (retval != -1UL)
		return 2;
	switch (err) {
	case EPERM:
	case EACCES:
	case EAGAIN:
	case EBUSY:
	case EOPNOTSUPP:
		return 1;
	default:
		return 0;
	}
}

/* Phase 3 of handle_syscall_ret: post-dispatch stats, hooks, and
 * cleanup.  Bumps the per-syscall errno-bucket histogram and the
 * unconditional entry->attempted counter, then under state == AFTER
 * runs the count-bound checks, the ret_objtype_via_post / entry->post
 * hooks, register_returned_fd, and prop_ring_push.  Finally runs
 * check_uid, entry->cleanup, rec_owned_drain, and generic_free_arg
 * unconditionally (teardown MUST run on every dispatched call,
 * including validator-rejected, --dry-run synthesised, and
 * SIGKILL'd-before-AFTER paths). */
static void syscall_ret_post_phase(struct syscallrecord *rec,
				   struct syscallentry *entry,
				   unsigned int call,
				   bool retfd_rejected,
				   bool rzs_rejected)
{
	/* Per-syscall errno-bucket histogram bump.  Sibling to the
	 * per_syscall_edges/calls counters in kcov_shm — those track
	 * coverage-side activity per syscall; this tracks return shape
	 * (success vs the six most-watched errno classes vs other).
	 * Surfaced via dump_stats() as a sibling block to the top-edges
	 * table so the operator can spot EFAULT-heavy vs EINVAL-heavy
	 * syscalls at a glance.  Gated on state == AFTER for the same
	 * reason the entry->failures/entry->errnos[] tallies above are:
	 * an EXTRA_FORK grandchild that was SIGKILL'd before AFTER
	 * leaves rec->retval / rec->errno_post holding whatever shm
	 * noise the previous syscall stamped, and we don't want to
	 * attribute that to either the surviving syscall slot or to
	 * bucket 0 (success).  kcov_shm itself is always allocated by
	 * kcov_init_global() regardless of per-child KCOV capability,
	 * but guard for NULL anyway to match the dump-side gate. */
	if (__atomic_load_n(&rec->state, __ATOMIC_ACQUIRE) == AFTER &&
	    kcov_shm != NULL && call < MAX_NR_SYSCALL) {
		unsigned int bucket;

		if (rec->retval != -1UL) {
			bucket = ERRNO_BUCKET_SUCCESS;
		} else {
			switch (rec->errno_post) {
			case EFAULT: bucket = ERRNO_BUCKET_EFAULT; break;
			case EINVAL: bucket = ERRNO_BUCKET_EINVAL; break;
			case ENOSYS: bucket = ERRNO_BUCKET_ENOSYS; break;
			case EPERM:  bucket = ERRNO_BUCKET_EPERM;  break;
			case EBADF:  bucket = ERRNO_BUCKET_EBADF;  break;
			case EAGAIN: bucket = ERRNO_BUCKET_EAGAIN; break;
			default:     bucket = ERRNO_BUCKET_OTHER;  break;
			}
		}
		__atomic_add_fetch(&kcov_shm->errno_state.per_syscall_errno[call][bucket],
				   1, __ATOMIC_RELAXED);

		/* Credential-class oracle (always on, no flag gate): mirror the
		 * just-classified bucket into the per-class success / EPERM /
		 * EINVAL / calls counters when the entry resolves to a known
		 * credential syscall.  No-op (single name-compare strcmp loop
		 * plus an early return) on the ~99% non-credential majority.
		 * Kept here so the bucket variable is already computed and the
		 * AFTER gate above already filtered out grandchild-killed and
		 * pre-validation paths -- the oracle should reflect only calls
		 * the kernel actually saw. */
		cred_oracle_record(entry, bucket);

		/* Stamp last_efault_at[] with the current total_calls so a
		 * future picker pass can bias away from syscalls stuck in
		 * pure-EFAULT regimes.  total_calls is the same counter
		 * last_edge_at[] uses, so the two fields stay directly
		 * comparable. */
		if (bucket == ERRNO_BUCKET_EFAULT) {
			unsigned long now_call =
				__atomic_load_n(&kcov_shm->coverage.total_calls,
						__ATOMIC_RELAXED);
			__atomic_store_n(&kcov_shm->errno_state.last_efault_at[call],
					 now_call, __ATOMIC_RELAXED);
		}

		/* errno-gradient-save CHEAP FIRST trigger.  PC-edge
		 * reward is too sparse to seed admission for validator-bound
		 * syscalls, but errno buckets already encode gate progress
		 * (EFAULT -> EINVAL -> EPERM/EBADF -> EAGAIN/0).  On the first
		 * non-EFAULT bucket per syscall per run window, bump the
		 * would-save shadow counter; if the --corpus-save-errno-grad-
		 * live A/B flag is on, also admit the args via
		 * CORPUS_SAVE_REASON_ERRNO.  Default-off keeps the corpus
		 * admission distribution byte-identical to before, while the
		 * shadow counter is always live so the would-be-save volume
		 * is observable.
		 *
		 * EFAULT (bit set deliberately skipped): the userspace-pointer
		 * noise floor; the queued errno-waste-decay handles
		 * EFAULT-heavy syscalls on the DECAY side, distinct from this
		 * SAVE side.  Bit indexes into errno_bucket_seen[call]; the
		 * fetch-or returns the prior mask so the "first time" test is
		 * atomic vs concurrent children racing the same syscall slot
		 * (loser sees prev & bit set and falls through; winner sees it
		 * clear and triggers exactly once for the first-discoverer). */
		if (bucket != ERRNO_BUCKET_EFAULT) {
			unsigned int bit = 1u << bucket;
			unsigned int prev = __atomic_fetch_or(
				&kcov_shm->errno_state.errno_bucket_seen[call], bit,
				__ATOMIC_RELAXED);

			if ((prev & bit) == 0) {
				__atomic_fetch_add(
					&shm->stats.errno_gradient.save_would_save,
					1UL, __ATOMIC_RELAXED);

				if (corpus_save_errno_grad_live &&
				    entry->sanitise == NULL) {
					__atomic_fetch_add(
						&shm->stats.errno_gradient.save_did_save,
						1UL, __ATOMIC_RELAXED);
					minicorpus_save_with_reason(rec,
						CORPUS_SAVE_REASON_ERRNO);
				}
			}
		}

		/* SHADOW errno-class gradient observation.  Pure
		 * measurement -- no admission / scoring / picking
		 * path consumes these writes; the only effect outside
		 * this block is the aggregate counters rendered by
		 * stats.c.  See the errno_gradient_* block in
		 * include/stats.h for the class axis and the SHADOW
		 * contract.
		 *
		 * Strictly-greater compare-exchange on the per-
		 * syscall last-class slot: only an upward transition
		 * (e.g. 0 -> 1, 1 -> 2, 0 -> 2) publishes the new
		 * class and bumps the aggregates.  Equal / downward
		 * transitions leave the slot and the counters
		 * untouched.  The CAS loop tolerates concurrent
		 * producers racing the same nr: a peer that publishes
		 * a larger class mid-loop refreshes `last` on the
		 * failed CAS, and our (now-no-longer-strictly-greater)
		 * observation drops out without a spurious bump.
		 * RELAXED throughout -- shadow predicate, the worst
		 * race outcome is a one-pick over/under-count of the
		 * aggregates, and live selection is not a consumer. */
		{
			unsigned int cls =
				errno_gradient_class(rec->retval,
				                     rec->errno_post);
			unsigned long last = __atomic_load_n(
				&shm->stats.errno_gradient.last_class[call],
				__ATOMIC_RELAXED);

			while ((unsigned long)cls > last) {
				if (__atomic_compare_exchange_n(
					&shm->stats.errno_gradient.last_class[call],
					&last, (unsigned long)cls,
					false,
					__ATOMIC_RELAXED,
					__ATOMIC_RELAXED)) {
					__atomic_fetch_add(
						&shm->stats.errno_gradient.crossings,
						1UL, __ATOMIC_RELAXED);
					if (cls == 1)
						__atomic_fetch_add(
							&shm->stats.errno_gradient.to_permstate,
							1UL, __ATOMIC_RELAXED);
					else /* cls == 2 (success) */
						__atomic_fetch_add(
							&shm->stats.errno_gradient.to_success,
							1UL, __ATOMIC_RELAXED);
					break;
				}
				/* CAS failed: `last` was refreshed in
				 * place to the peer's freshly-published
				 * value; loop test re-evaluates. */
			}
		}
	}

	/* attempted stays ungated: an attempted invocation IS still an
	 * attempt even if the grandchild never reached AFTER, and
	 * (attempted - successes - failures) gives operators visibility
	 * on how many EXTRA_FORK grandchildren are getting killed. */
	__atomic_add_fetch(&entry->attempted, 1, __ATOMIC_RELAXED);

	/* enforce_count_bound, entry->post, and register_returned_fd all
	 * read rec->aN / rec->retval and would act on the previous
	 * syscall's stale shm state if the grandchild was SIGKILL'd
	 * before AFTER.  Gate the whole batch on state == AFTER so a
	 * killed grandchild can't trigger a spurious count-bound warning,
	 * a .post handler acting on stale args, or a stale fd getting
	 * inserted into the OBJ_LOCAL pool. */
	if (__atomic_load_n(&rec->state, __ATOMIC_ACQUIRE) == AFTER) {
		enforce_count_bound(entry, rec);
		validate_ret_bound(entry, rec);

		/* Post-derived secondary-object registrar runs ahead of
		 * entry->post: per-syscall .post handlers (pipe,
		 * socketpair, io_setup, timer_create) clear rec->post_state
		 * as part of their cleanup pass, and the hook reads
		 * post_state / rec->aN to derive what to register.  Same
		 * retfd/rzs-rejected gate as entry->post -- a fabricated
		 * retval shouldn't drive any registration (timer_create is
		 * RET_ZERO_SUCCESS with a .ret_objtype_via_post that reads
		 * *post_state on the success branch; without the rzs gate
		 * a stomped retval would feed a garbage timer_t into the
		 * OBJ_TIMERID pool). */
		if (entry->ret_objtype_via_post &&
		    !retfd_rejected && !rzs_rejected)
			entry->ret_objtype_via_post(rec);

		/* Telemetry-only liveness gate.  Runs immediately before
		 * the post handler so the slot values it inspects match
		 * what entry->post is about to read.  Bumps
		 * arena_ptr_stale_caught_{arg,post_state} on detection;
		 * does NOT mutate the slot or skip entry->post -- the
		 * kernel has already observed whatever value sat here, so
		 * post-dispatch coercion would just scribble shared state
		 * without changing the syscall outcome. */
		arena_liveness_probe(entry, rec);

		/* Skip entry->post on a rejected RET_FD or RET_ZERO_SUCCESS:
		 * the handler would be acting on a fabricated retval,
		 * attribution already happened inside the rejection site.
		 * register_returned_fd() below already short-circuits on
		 * (long)rec->retval < 0 so the coerced -1UL makes it a
		 * no-op there regardless; prop_ring_push() likewise filters
		 * the coerced sret == -1 case before capture. */
		if (entry->post && !retfd_rejected && !rzs_rejected)
		    entry->post(rec);

		register_returned_fd(entry, rec);

		/* Capture qualifying non-fd small-int returns into the
		 * per-child propagation ring.  Same state == AFTER gate
		 * as the fd path; same gate ordering after the canary
		 * check so a scribbled retval doesn't pollute the ring.
		 * The push routine applies the OBJ_NONE / range / fd-
		 * alias filters internally so the dispatcher stays
		 * agnostic to the capture policy. */
		prop_ring_push(this_child(), entry, rec);
	}

	/* check_uid inspects current process state, not rec; safe to
	 * run regardless.  generic_free_arg frees ARG_PATHNAME /
	 * ARG_IOVEC / ARG_SOCKADDR buffers that the parent allocated
	 * before do_syscall ran -- they exist independent of whether
	 * the grandchild reached AFTER and MUST be freed to avoid
	 * leaking. */
	check_uid();

	/* Unconditional per-syscall .cleanup hook.  Fires exactly once
	 * per dispatched call -- handle_syscall_ret() is the single
	 * funnel every syscall flows through, with no early returns
	 * between the dispatch tail and this point.  No state == AFTER
	 * gate: cleanup MUST run on the validator_rejected early-EINVAL
	 * skip (state IS AFTER, synthesised in __do_syscall), on the
	 * --dry-run synthesised ENOSYS path (same), AND on the
	 * EXTRA_FORK grandchild that was SIGKILL'd before AFTER (state
	 * stays at whatever the previous syscall left it at) -- all
	 * three paths still allocated sanitiser-owned buffers in
	 * generate_syscall_args() that must be reclaimed.  No
	 * retfd_rejected / rzs_rejected gate either: cleanup is
	 * teardown, not result interpretation, so a fabricated retval
	 * does not change what needs freeing.
	 *
	 * Ordering: AFTER entry->post (which interprets the kernel
	 * return -- closes a returned fd, calls publish_resource,
	 * mq_unlinks the named queue) and BEFORE generic_free_arg()
	 * (which runs the per-argtype cleanup for ARG_PATHNAME /
	 * ARG_IOVEC / ARG_SOCKADDR slots).  This lets .post stay a
	 * pure successful-result inspector while .cleanup owns the
	 * syscall-level teardown. */
	if (entry->cleanup != NULL)
		entry->cleanup(rec);

	/* Default cleanup: drain any pointers a sanitiser / generator /
	 * .cleanup hook registered via rec_own().  Runs unconditionally
	 * for the same reasons entry->cleanup above and generic_free_arg
	 * below do (no state == AFTER gate, no retfd/rzs gate) -- a
	 * registered pointer is heap memory we own regardless of how the
	 * dispatch played out.  Ordered AFTER the per-syscall .cleanup
	 * hook so a handler can register additional pointers from inside
	 * its hook body (e.g. a snap freed conditionally on rec->retval)
	 * and still have them swept here in the same cleanup phase.
	 * Empty on every dispatched call until Phase 2 migrations begin
	 * populating the carrier; until then this is a NULL-fast-path
	 * read of rec->owned_count and an early return -- behaviour is
	 * byte-identical to pre-change. */
	rec_owned_drain(rec);

	generic_free_arg(entry, rec);
}

void handle_syscall_ret(struct syscallrecord *rec, struct syscallentry *entry)
{
	unsigned int call = rec->nr;
	bool retfd_rejected;
	bool rzs_rejected = false;

	syscall_ret_validate_phase(rec, entry, &retfd_rejected, &rzs_rejected);
	syscall_ret_dispatch_phase(rec, entry, call);
	syscall_ret_post_phase(rec, entry, call, retfd_rejected, rzs_rejected);
}
