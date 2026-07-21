/*
 * Functions for actually doing the system calls.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "arch.h"
#include "arg_coupling.h"
#include "argtype-ops.h"
#include "child.h"
#include "cred_throttle.h"
#include "debug.h"
#include "deferred-free.h"
#include "fd-event.h"
#include "fd.h"
#include "kcov.h"
#include "maps.h"
#include "minicorpus.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "prop_ring.h"
#include "random.h"
#include "results.h"
#include "sanitise.h"
#include "shm.h"
#include "signals.h"
#include "stats_ring.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "uid.h"
#include "utils.h"

#ifdef ARCH_IS_BIARCH
/*
 * This routine does 32 bit syscalls on 64 bit kernel.
 * 32-on-32 will just use syscall() directly from do_syscall() because do32bit flag is biarch only.
 */
static long syscall32(unsigned int call,
	unsigned long a1, unsigned long a2, unsigned long a3,
	unsigned long a4, unsigned long a5, unsigned long a6)
{
	long __res = 0;

#if defined(DO_32_SYSCALL)
	/* If we have CONFIG_IA32_EMULATION unset, we will segfault.
	 * Detect this case, and force 64-bit only.
	 */
	if (__atomic_load_n(&shm->syscalls32_succeeded, __ATOMIC_RELAXED) == false) {
		if (__atomic_load_n(&shm->syscalls32_attempted, __ATOMIC_RELAXED) >= (max_children * 2)) {
			unsigned int i;
			bool did_disable = false;
			unsigned int snap_attempted = 0;

			lock(&shm->syscalltable_lock);

			/* check another thread didn't already do this. */
			if (shm->nr_active_32bit_syscalls != 0) {
				snap_attempted = __atomic_load_n(&shm->syscalls32_attempted, __ATOMIC_RELAXED);

				for (i = 0; i < max_nr_32bit_syscalls; i++) {
					struct syscallentry *entry = syscalls_32bit[i].entry;

					if (entry == NULL)
						continue;

					if (entry->active_number != 0)
						deactivate_syscall_nolock(i, true);
				}
				/* The per-call deactivate path has already cleared the
				 * cached validity bit when nr_active hit zero; pin it
				 * here so the auto-disable point is self-evidently
				 * coherent even if the loop above ever exits early. */
				__atomic_store_n(&shm->valid_syscall_table_32, false, __ATOMIC_RELAXED);
				did_disable = true;
			}

			unlock(&shm->syscalltable_lock);

			if (did_disable)
				output(0, "Tried %d 32-bit syscalls unsuccessfully. Disabling all 32-bit syscalls.\n",
						snap_attempted);
		}

		__atomic_add_fetch(&shm->syscalls32_attempted, 1, __ATOMIC_RELAXED);
	}

	DO_32_SYSCALL

	if ((unsigned long)(__res) >= (unsigned long)(-133)) {
		errno = -(__res);
		__res = -1;
	}

	__atomic_store_n(&shm->syscalls32_succeeded, true, __ATOMIC_RELAXED);

#else
	#error Implement 32-on-64 syscall macro for this architecture.
#endif
	return __res;
}
#else
#define syscall32(a,b,c,d,e,f,g) 0
#endif /* ARCH_IS_BIARCH */

/*
 * Maybe arm /proc/self/fail-nth so the next syscall sees an allocation
 * failure on its Nth slab/page alloc.  Returns true if we wrote a value.
 *
 * We deliberately do this *here*, after all sanitise_*() and arg-generation
 * has happened, so the fault hits the kernel's path through the syscall
 * itself rather than any of trinity's setup allocations.
 *
 * Skip on the EXTRA_FORK throwaway path (state == GOING_AWAY): the
 * grandchild inherits the fd, but the file inode refers to the opener's
 * (i.e. parent child's) task — writing through it would arm fault
 * injection on the *parent*'s next syscall, not the grandchild's.
 */
static bool maybe_inject_fault(struct childdata *child, enum syscallstate state)
{
	char buf[16];
	int n, len;

	if (child == NULL || child->fail_nth_fd == -1)
		return false;

	if (state != BEFORE)
		return false;

	if (!ONE_IN(20))
		return false;

	n = RAND_RANGE(1, 8);
	len = snprintf(buf, sizeof(buf), "%d", n);

	if (write(child->fail_nth_fd, buf, (size_t)len) != len)
		return false;

	return true;
}

static void child_watchdog_evict_fd(int fd, void *ctx)
{
	struct childdata *child = ctx;

	if (child->fd_event_ring != NULL)
		fd_event_enqueue(child->fd_event_ring, FD_EVENT_EVICT, fd);
}

/*
 * SHADOW-only Phase-1 per-syscall clean-vs-noisy attribution sampler.
 * See the field comments on per_syscall_edges_noisy /
 * per_syscall_noisy_samples in include/kcov.h and the extern comment on
 * frontier_noise_sample in include/params.h.
 *
 * noisy_sample_ctr is a file-scope integer, per-child by virtue of the
 * fork isolation the tree already relies on for sigalrm_pending and
 * in_do_syscall.  Deliberately NOT a global atomic: the cadence gate is
 * a single non-atomic increment on child-local state, so the sampler
 * does not add cross-child cacheline bounce (which would defeat the
 * entire point of sampling).  When frontier_noise_sample == 0 (default),
 * the _begin helper short-circuits before touching the shared
 * edges_found counter, so the default build issues zero new hot-path
 * loads on the syscall dispatch path.
 */
static unsigned int noisy_sample_ctr;

static inline bool syscall_noisy_sample_begin(unsigned long *before_out)
{
	unsigned int n = __atomic_load_n(&frontier_noise_sample,
					 __ATOMIC_RELAXED);

	if (n == 0)
		return false;
	if (kcov_shm == NULL)
		return false;
	if (++noisy_sample_ctr < n)
		return false;
	noisy_sample_ctr = 0;
	*before_out = __atomic_load_n(&kcov_shm->coverage.edges_found,
				      __ATOMIC_RELAXED);
	return true;
}

static inline void syscall_noisy_sample_end(unsigned int nr,
					    unsigned long before)
{
	unsigned long after;
	unsigned long delta;

	after = __atomic_load_n(&kcov_shm->coverage.edges_found, __ATOMIC_RELAXED);
	/* Guard the unsigned subtraction: RELAXED loads of a concurrently-
	 * incremented atomic can invert in principle, and a wrap-underflow
	 * would attribute a colossal delta to this syscall.  Clamp to zero
	 * on the pathological ordering. */
	delta = (after >= before) ? (after - before) : 0UL;

	__atomic_fetch_add(&kcov_shm->per_syscall.per_syscall_edges_noisy[nr], delta,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&kcov_shm->per_syscall.per_syscall_noisy_samples[nr], 1UL,
			   __ATOMIC_RELAXED);
}

static void __do_syscall(struct syscallrecord *rec, struct syscallentry *entry,
			 enum syscallstate state,
			 struct kcov_child *kc, struct childdata *child)
{
	unsigned long ret = 0;
	unsigned long a1, a2, a3, a4, a5, a6;
	bool fault_armed = false;
	int saved_errno = 0;
	int call;
	bool needalarm;

	errno = 0;

	call = rec->nr + SYSCALL_OFFSET;
	needalarm = entry->flags & NEED_ALARM;

	srec_publish_begin(rec);
	__atomic_store_n(&rec->state, state, __ATOMIC_RELAXED);
	/* Stamp the wholesale-stomp canary just before dispatch so
	 * handle_syscall_ret() can tell whether anything overwrote
	 * the rec while the kernel had control.  One store on the hot
	 * path; the matching load is paired with the AFTER snapshot
	 * read inside the post handler. */
	rec->_canary = REC_CANARY_MAGIC;
	srec_publish_end(rec);

	/* Second blanket_address_scrub() pass, post-publish_end and
	 * pre-snapshot: closes the sibling-stomp window between the
	 * sanitise-time scrub at the tail of generate_syscall_args() and
	 * the local snapshot below.  Same range-aware predicate and same
	 * address_scrub_mask (honouring SKIP_BLANKET_SCRUB) as the first
	 * pass — only the timing moves. */
	blanket_address_scrub(entry, rec);

	/* Cross-arg consistency check + coupled-pair repair: catch
	 * (buf_ptr, count) pairs the kernel would reject at its earliest
	 * validation step, and clamp over-extent lengths in place so the
	 * syscall walks real kernel code instead of copy-faulting at
	 * import.  Runs BEFORE the local snapshot so any repair mutation
	 * to rec->aN flows through to the values the kernel actually sees
	 * (and to dispatch_args / arg_shadow below).  On reject synthesize
	 * a -1/EINVAL AFTER state so handle_syscall_ret() accounts the
	 * rejection identically to a real early-EINVAL failure.  Zero the
	 * kcov trace count header manually because kcov_enable_trace
	 * (which usually owns that zeroing) never runs on the skip path
	 * and the caller's kcov_collect() would otherwise re-process the
	 * previous syscall's PCs against this slot. */
	if (validate_arg_coupling(rec) != 0) {
		validator_rejected_bump();
		if (kc != NULL && kc->active) {
			if (kc->mode == KCOV_MODE_PC && kc->trace_buf != NULL)
				__atomic_store_n(&kc->trace_buf[0], 0,
						 __ATOMIC_RELAXED);
			else if (kc->mode == KCOV_MODE_CMP &&
				 kc->cmp_trace_buf != NULL)
				__atomic_store_n(&kc->cmp_trace_buf[0], 0,
						 __ATOMIC_RELAXED);
		}
		/* Clear dispatch_args_valid so cmp_hints_collect()'s RedQueen
		 * attribution scan (and the field-scoped scan) does not read
		 * the PREVIOUS successful call's dispatch_args[] against this
		 * call's rec->nr / entry->num_args.  Belt-and-braces alongside
		 * the trace-buf header clear above: the header clear alone is
		 * enough on the happy kc->active path, but any consumer that
		 * inspects dispatch_args_valid without also gating on the
		 * per-call trace-buf count would otherwise misattribute
		 * constants to the wrong (nr, aN). */
		rec->dispatch_args_valid = false;
		srec_publish_begin(rec);
		rec->errno_post = EINVAL;
		rec->retval = (unsigned long) -1L;
		rec->validator_rejected = true;
		__atomic_store_n(&rec->state, AFTER, __ATOMIC_RELEASE);
		srec_publish_end(rec);
		return;
	}

	/* Snapshot the argument slots before dispatch.  rec lives in
	 * shared memory and a sibling child can stomp rec->aN mid-flight
	 * (the per-arg snapshot pattern in .post handlers exists for
	 * exactly this reason).  We send the snapshots to the kernel
	 * and re-read them from the locals in the watchdog eviction
	 * block below so a sibling stomp between syscall return and the
	 * eviction read cannot redirect us to a fabricated fd value. */
	a1 = rec->a1;
	a2 = rec->a2;
	a3 = rec->a3;
	a4 = rec->a4;
	a5 = rec->a5;
	a6 = rec->a6;

	/* Non-tripwire dispatch-arg snapshot, shared with
	 * cmp_hints_collect()'s RedQueen attribution scan.  Captured here
	 * from the same locals the kernel will see (post the second
	 * blanket_address_scrub above) so the scan attributes against the
	 * kernel-visible values rather than live rec->aN, which a sibling
	 * stomp can rewrite between dispatch and the post-handler read.
	 * Distinct from rec->arg_shadow[] populated below: that array is
	 * opt-in per syscall (entry->arg_snapshot_mask) and bumps a
	 * tripwire on mismatch via get_arg_snapshot(); this snapshot is
	 * always populated and read directly, suited to a scanning
	 * consumer rather than a per-slot result oracle. */
	rec->dispatch_args[0] = a1;
	rec->dispatch_args[1] = a2;
	rec->dispatch_args[2] = a3;
	rec->dispatch_args[3] = a4;
	rec->dispatch_args[4] = a5;
	rec->dispatch_args[5] = a6;
	rec->dispatch_args_valid = true;

	/* Populate rec->arg_shadow[] from the local a1..a6 about to be
	 * passed to the kernel, so opted-in post handlers reading via
	 * get_arg_snapshot() see exactly what the kernel saw.  Captured
	 * here -- after the second blanket_address_scrub above and from
	 * the locals (immune to a sibling stomp between BEFORE and AFTER)
	 * -- so the shadow holds precisely what the kernel saw.  The only
	 * stomp the shadow can miss is one that lands after dispatch
	 * began, which IS the bug class arg_shadow_stomp is meant to
	 * surface. */
	{
		/* arg_snapshot_mask only carries six valid bits (one per
		 * syscall arg).  Mask the byte to 0x3f before iterating: a
		 * stray bit 6/7 -- whether from a sanitiser writing the wrong
		 * field or from future growth past 6 args without bumping
		 * arg_shadow[] -- would let __builtin_ctz return 6 or 7 and
		 * the rec->arg_shadow[i] store below would scribble past the
		 * six-entry array.  The switch default's val=0 alone is not
		 * enough; it only neuters the value, not the index. */
		uint8_t mask = (uint8_t)(entry->arg_snapshot_mask & 0x3fu);

		rec->arg_snapshot_mask = mask;
		while (mask != 0) {
			unsigned int i = (unsigned int)__builtin_ctz(mask);
			unsigned long val;

			switch (i + 1) {
			case 1: val = a1; break;
			case 2: val = a2; break;
			case 3: val = a3; break;
			case 4: val = a4; break;
			case 5: val = a5; break;
			case 6: val = a6; break;
			default: val = 0; break;
			}
			rec->arg_shadow[i] = val;
			mask &= (uint8_t)(mask - 1);
		}
	}

	/*
	 * --dry-run: run the full argument-generation/sanitise pipeline
	 * (already complete by the time we reach here) and the post
	 * handlers, but never execute the syscall.  Synthesize a -1/ENOSYS
	 * AFTER state so the post path accounts it as an early failure --
	 * handle_failure() runs for coverage while the success-gated
	 * registrars (handle_success, register_returned_fd, prop_ring_push)
	 * and entry->post all short-circuit on retval == -1UL, issuing no
	 * syscall of their own.  deactivate_enosys() is skipped for dry-run
	 * at its call site so the synthetic ENOSYS does not drain the
	 * syscall table.  Zero the kcov trace header manually (kcov_enable
	 * never ran on this skip path) so the caller's kcov_collect() does
	 * not re-process the previous syscall's PCs -- mirroring the
	 * validate_arg_coupling() reject above.  Lets ASAN drive the
	 * generators on any host without firing a fuzzed syscall.
	 */
	if (dry_run) {
		if (kc != NULL && kc->active) {
			if (kc->mode == KCOV_MODE_PC && kc->trace_buf != NULL)
				__atomic_store_n(&kc->trace_buf[0], 0,
						 __ATOMIC_RELAXED);
			else if (kc->mode == KCOV_MODE_CMP &&
				 kc->cmp_trace_buf != NULL)
				__atomic_store_n(&kc->cmp_trace_buf[0], 0,
						 __ATOMIC_RELAXED);
		}
		/* Clear dispatch_args_valid: the snapshot above populated
		 * dispatch_args[] with this call's args, but the syscall
		 * never entered the kernel and generated no CMP records for
		 * cmp_hints_collect() to attribute against those slots.
		 * Leaving the flag true would let a stale trace-buf count
		 * (if the kc->active clear above was skipped) drive the
		 * RedQueen attribution scan into a syscall that never ran. */
		rec->dispatch_args_valid = false;
		srec_publish_begin(rec);
		rec->errno_post = ENOSYS;
		rec->retval = (unsigned long) -1L;
		__atomic_store_n(&rec->state, AFTER, __ATOMIC_RELEASE);
		srec_publish_end(rec);
		return;
	}

	/* Arm the alarm after the publish-end above: the publish
	 * brackets are the ordering anchor.  SIGALRM firing inside the
	 * bracketed region would be caught by the handler whose
	 * siglongjmp then orphans the alarm, so arming stays outside
	 * the brackets. */
	if (needalarm) {
		/*
		 * Restore the inner-watchdog handler before arming.  Both
		 * SIGALRM and SIGXCPU appear in settable_signals[], so a
		 * fuzzed rt_sigaction call in this child can overwrite the
		 * 1-second-timeout disposition; without a reinstall the
		 * blocking NEED_ALARM syscall then rides only the ~30-second
		 * outer watchdog.  The helper is restricted to the two
		 * watchdog signals and bumps the paired clobbered/reinstalled
		 * counters so both the incidence and the repair rate stay
		 * measurable.
		 */
		watchdog_reinstall_if_clobbered();
		(void)alarm(1);
	}

	/* Per-child mode picked once in kcov_init_child: PC-mode children
	 * enable the PC fd (per-thread or remote) and feed edge coverage,
	 * CMP-mode children enable the cmp fd and feed comparison-operand
	 * hints.  Exactly one fd is enabled per syscall because the kernel's
	 * one-`t->kcov`-per-task rule returns -EBUSY on a second simultaneous
	 * enable; the fleet-wide PC/CMP signal split comes from the
	 * population mix instead of per-call mode toggling. */
	/* SHADOW-only Phase-1 per-syscall clean-vs-noisy attribution sampler.
	 * When frontier_noise_sample > 0 and the counter has ticked over,
	 * snapshot edges_found immediately before kcov_enable_* and again
	 * after kcov_disable so the delta captures the global new-edge
	 * accrual across this syscall's enable/disable window (the "noisy"
	 * global-attribution denominator complementary to per_syscall_edges'
	 * per-thread clean numerator).  Gated on nr < MAX_NR_SYSCALL to
	 * match the per_syscall_edges_noisy[] array bound and skip childop-
	 * base nr values.  The sample_begin helper short-circuits at N==0,
	 * kcov_shm==NULL, or when the child-local counter has not yet
	 * ticked to N, so the default build issues zero new edges_found
	 * loads. */
	unsigned long noisy_before = 0;
	bool noisy_sampled = false;

	if (rec->nr < MAX_NR_SYSCALL)
		noisy_sampled = syscall_noisy_sample_begin(&noisy_before);

	if (rec->do32bit == false) {
		if (kc != NULL && kc->mode == KCOV_MODE_CMP) {
			kcov_enable_cmp(kc);
		} else if (kc != NULL && kc->remote_mode) {
			kcov_enable_remote(kc, child != NULL ? child->num : 0, rec->nr);
		} else {
			kcov_enable_trace(kc);
		}
		fault_armed = maybe_inject_fault(child, state);
		ret = syscall(call, a1, a2, a3, a4, a5, a6);
		saved_errno = errno;
		kcov_disable(kc);
	} else {
		if (kc != NULL && kc->mode == KCOV_MODE_CMP) {
			kcov_enable_cmp(kc);
		} else if (kc != NULL && kc->remote_mode) {
			kcov_enable_remote(kc, child != NULL ? child->num : 0, rec->nr);
		} else {
			kcov_enable_trace(kc);
		}
		fault_armed = maybe_inject_fault(child, state);
		ret = syscall32(call, a1, a2, a3, a4, a5, a6);
		saved_errno = errno;
		kcov_disable(kc);
	}

	if (noisy_sampled)
		syscall_noisy_sample_end(rec->nr, noisy_before);

	/* fail-nth resets to 0 in the kernel after the syscall completes.
	 * Tally whether the armed fault actually triggered (-ENOMEM) vs
	 * went unconsumed (the syscall didn't reach an allocation we hit). */
	if (fault_armed) {
		if (child != NULL) {
			stats_ring_enqueue(child->stats_ring,
					   STATS_FIELD_FAULT_INJECTED, 0, 1);
			if (ret == (unsigned long)-1L && saved_errno == ENOMEM)
				stats_ring_enqueue(child->stats_ring,
						   STATS_FIELD_FAULT_CONSUMED,
						   0, 1);
		} else {
			parent_stats.fault_injected++;
			if (ret == (unsigned long)-1L && saved_errno == ENOMEM)
				parent_stats.fault_consumed++;
		}
	}

	/* If we became tainted, get out as fast as we can. */
	if (is_tainted() == true) {
		panic(EXIT_KERNEL_TAINTED);
		_exit(EXIT_KERNEL_TAINTED);
	}

	if (needalarm)
		(void)alarm(0);

	/* In-child watchdog eviction window.  The 1s alarm above bounds
	 * how long the kernel can hold us inside a single syscall; on
	 * fire it interrupts the syscall with EINTR and the handler in
	 * signals.c sets sigalrm_pending.  We do the fd-eviction work
	 * HERE -- after the syscall has returned and alarm(0) has
	 * disarmed, but BEFORE the lock region below publishes state =
	 * AFTER -- rather than from the signal handler (async-signal-
	 * unsafe to walk fd_event_ring there) or from the child main
	 * loop's sigalrm_pending branch (which the BEFORE -> AFTER
	 * transition would otherwise race past, leaving the eviction
	 * unreachable).  The conjunction below is the conservative
	 * "our watchdog actually fired on a blocking syscall" predicate:
	 * sigalrm_pending alone can be set by any fuzzed SIGALRM source,
	 * but the combination of our own alarm being armed, the syscall
	 * returning EINTR, and the child running a normal syscall op is
	 * specific to the watchdog path. */
	if (needalarm && sigalrm_pending &&
	    ret == (unsigned long)-1L && saved_errno == EINTR &&
	    child != NULL && child->op_type == CHILD_OP_SYSCALL) {
		/* Gate the bookkeeping on "the syscall has fd-bearing arg
		 * slots", matching the slot-set for_each_fd_arg() will walk
		 * (fd_arg_mask plus the ARG_SOCKETINFO-in-slot-0 mirror).
		 * Bump stats and reset fd_lifetime once per stuck-syscall
		 * event, regardless of how many of those args' raw values
		 * actually pass the rlimit check inside the walk. */
		uint8_t gate = entry->fd_arg_mask;
		if (entry->argtype[0] == ARG_SOCKETINFO)
			gate |= 0x01;

		if (gate != 0) {
			unsigned long args[6] = { a1, a2, a3, a4, a5, a6 };

			child->fd_lifetime = 0;

			stats_ring_enqueue(child->stats_ring,
					   STATS_FIELD_WATCHDOG_FD_EVICT,
					   0, 1);

			for_each_fd_arg(entry, args,
					child_watchdog_evict_fd, child);
		}

		/* Eviction handled here; clear the pending flag so the child
		 * main loop's sigalrm_pending branch sees a no-op for this
		 * SIGALRM.  The housekeeping there (alarm(0) and the same
		 * pending clear) still covers other op_type paths and races
		 * where the flag is set outside this dispatch window. */
		sigalrm_pending = 0;
	}

	srec_publish_begin(rec);
	rec->errno_post = saved_errno;
	rec->retval = ret;
	__atomic_store_n(&rec->state, AFTER, __ATOMIC_RELEASE);
	srec_publish_end(rec);
}

/* This is a special case for things like execve, which would replace our
 * child process with something unknown to us. We use a 'throwaway' process
 * to do the execve in, and let it run for a max of a second before we kill it
 */
static void do_extrafork(struct syscallrecord *rec, struct syscallentry *entry,
			 struct childdata *child)
{
	pid_t pid = 0;
	pid_t extrapid;

#ifdef __SANITIZE_ADDRESS__
	/* ASAN's __asan_handle_no_return runs at the fork/exec boundary
	 * and trips a CHECK in PoisonShadow when called from this path
	 * (PlatformUnpoisonStacks receives bogus stack bounds, aborts
	 * with "AddrIsAlignedByGranularity != 0").  Downstream EAGAIN
	 * mmap failures in the grandchild's ASAN allocator follow from
	 * the same CLONE_VM-shared-address-space state.  Skip the extra
	 * fork on sanitizer builds; the regular fuzz path stays. */
	(void)rec; (void)entry;
	goto out;
#endif

	extrapid = fork();
	if (extrapid == 0) {
		/* grand-child */
		char childname[]="trinity-subchild";
		prctl(PR_SET_NAME, (unsigned long) &childname);

		/*
		 * Flag ourselves so child_fault_handler() skips the fault
		 * beacon stamp on a grand-child crash.  this_child() in the
		 * grand-child returns the parent worker's childdata (cached
		 * via COW-inherited cached_pid that no one updated across
		 * this fork), so without the gate a SIGSEGV here would mis-
		 * attribute the death to the parent worker and retire it.
		 * Set before __do_syscall so any synchronous fault inside
		 * the throwaway syscall is covered.
		 */
		in_extrafork_grandchild = 1;

		__do_syscall(rec, entry, GOING_AWAY, NULL, child);
		/* if this was for eg. an successful execve, we should never get here.
		 * if it failed though... */
		_exit(EXIT_SUCCESS);
	}

	/* misc failure. */
	if (extrapid == -1) {
		/* Parent already allocated snap in sanitise; post handler will
		 * not run because state never reaches AFTER. Free snap here. */
		if (entry->post != NULL)
			entry->post(rec);
		goto out;
	}

	/* small pause to let grandchild do some work. */
	if (pid_alive(extrapid) == true)
		usleep(100);

	/* Bound the loop to ~1 second (1000 * 1ms) so a D-state
	 * grandchild can't stall us forever.
	 */
	for (int i = 0; pid == 0 && i < 1000; i++) {
		int childstatus;

		pid = waitpid_eintr(extrapid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		usleep(1000);
	}

	/* Timed out, or waitpid errored. Force-kill and reap to prevent zombies. */
	if (pid <= 0) {
		kill(extrapid, SIGKILL);
		(void)waitpid_eintr(extrapid, NULL, 0);
	}

	/* Grandchild died before reaching __do_syscall's AFTER block, so
	 * handle_syscall_ret will skip entry->post (state != AFTER gate).
	 * The parent-side allocations referenced by rec->post_state would
	 * otherwise leak onto this worker's heap on every grandchild
	 * timeout (~254 KiB worst case for execve / execveat). Invoke
	 * entry->post here so it frees post_state.
	 *
	 * Safe because the only EXTRA_FORK syscalls with a post handler
	 * today are execve and execveat, both of which inspect
	 * rec->post_state exclusively (no dependency on rec->retval /
	 * errno_post / state). Any future EXTRA_FORK syscall whose post
	 * handler reads those fields must gate them on state == AFTER
	 * itself.
	 *
	 * No lock: grandchild was SIGKILL'd and reaped, no contender. */
	if (__atomic_load_n(&rec->state, __ATOMIC_RELAXED) != AFTER &&
	    entry->post != NULL)
		entry->post(rec);

out:
	/* do_extrafork bypasses the kcov_enable / syscall / kcov_disable
	 * bracket entirely -- the grandchild runs __do_syscall with
	 * kc=NULL, so the worker's trace_buf[0] still holds the count
	 * from the previous bracketed syscall.  Without the trace-header
	 * reset (inside kcov_note_extrafork) the caller's post-call
	 * kcov_collect() would re-read that count and re-account the
	 * prior call's PCs as EXTRA_FORK coverage, skewing total_calls /
	 * per_syscall_calls / warm-known-hits / diagnostics counters.
	 * Pass rec->nr so the helper can also bump
	 * per_syscall_extrafork_calls[nr]: the missing kcov_collect()
	 * means execve/execveat/vfork never touch per_syscall_calls[] or
	 * per_syscall_edges[], so downstream productivity ratios need a
	 * dedicated denominator to tell "EXTRA_FORK, coverage inherently
	 * unmeasurable via kcov" from "dead syscall". */
	kcov_note_extrafork(&child->kcov, rec->nr);
}


void generic_post_close_fd(struct syscallrecord *rec)
{
	long ret = (long)rec->retval;
	if (ret >= 0 && ret < (1 << 20))
		close((int)ret);
}

/*
 * Source of truth for the per-syscall return-type contract consumed by
 * reject_corrupt_retfd, the RZS gate in syscall_ret_validate_phase, and
 * validate_ret_bound below.
 *
 * Prefer entry->rettype: it is stamped once at table-init time in
 * copy_syscall_table() and never rewritten after, so a sibling stomp
 * targeting per-rec slots in shm cannot drift it.  rec->rettype lives
 * inside struct syscallrecord alongside rec->retval / rec->errno_post,
 * is rewritten on every dispatch from generate_syscall_args(), and is
 * directly exposed to the same value-result sibling-stomp class the
 * rzs/retfd validators are meant to catch against rec->retval.  When
 * that stomp lands on rec->rettype itself the validator misattributes
 * the corruption to a syscall whose static contract is unambiguous
 * (e.g. getpgrp returning its own pid is gated as if it had been a
 * zero-success syscall returning a non-zero value, because rec->rettype
 * was scribbled from RET_PID_T to RET_ZERO_SUCCESS between dispatch and
 * the gate).  Sourcing from entry sidesteps that class for every syscall
 * that declares a static rettype.
 *
 * Op-multiplexed entries (fcntl, futex) leave entry->rettype unset
 * (RET_NONE) and rely on their .sanitise hook to publish rec->rettype
 * per cmd at dispatch time.  Fall through to rec for those so the
 * per-cmd contract still drives the gate.
 */
static inline int effective_rettype(const struct syscallentry *entry,
				    const struct syscallrecord *rec)
{
	if (entry->rettype != RET_NONE)
		return entry->rettype;
	return rec->rettype;
}

/*
 * Blanket retval bound for RET_FD handlers at the do_syscall layer.
 * Complements the add_object()-side check: that gate fires only on
 * RET_FD entries that declare a ret_objtype and reach the universal
 * pool-registration chokepoint.  Roughly 19 RET_FD entries instead
 * carry bespoke .post handlers that consume the returned fd without
 * ever calling add_object() -- the generic_post_close_fd users
 * (signalfd, signalfd4, fsmount, open_tree, open_tree_attr,
 * memfd_secret, pidfd_getfd), perf_event_open's close-on-fail path,
 * futex(FUTEX_FD) (which has no retval check at all), and a handful
 * of others.  Without a chokepoint at this layer a wholesale-stomped
 * or upper-bit-corrupt rec->retval whose lower bits happen to be
 * positive slips past the "(long)retval >= 0" gates these handlers
 * use and is fed straight back to the kernel as a real fd by close()
 * (or worse, lands on a file-table entry an unrelated path opened).
 *
 * 1<<20 = 1048576 matches the kernel's NR_OPEN ceiling
 * (include/uapi/linux/fs.h), the absolute upper bound RLIMIT_NOFILE
 * may be raised to on every distro we exercise.  No legitimate RET_FD
 * handler treats an out-of-range value as anything but a kernel ABI
 * violation, so the validator firing IS the bug report.
 *
 * Rettype is read via effective_rettype(): static-contract entries are
 * sourced from entry->rettype (immune to per-rec stomp), op-multiplexed
 * entries (fcntl F_DUPFD*, futex FUTEX_FD) fall through to the
 * sanitise-published rec->rettype so the per-cmd contract still applies.
 *
 * On rejection, coerce rec->retval = -1UL and rec->errno_post =
 * EINVAL.  Every existing .post handler short-circuits on
 * (long)retval < 0, register_returned_fd() likewise skips the < 0
 * branch, so the coerced shape papers over the corruption for all
 * downstream consumers in one place.  Sub-attribution by syscall
 * routes through post_handler_corrupt_ptr_bump's per-handler ring
 * via the rec it's passed; the _dispatch wrapper additionally feeds
 * this site's caller PC into the per-PC ring so the dump can tell
 * blanket-validator rejections of a syscall apart from that same
 * syscall's own .post handler rejections.
 */
static bool reject_corrupt_retfd(const struct syscallentry *entry,
				 struct syscallrecord *rec)
{
	long s;

	if (effective_rettype(entry, rec) != RET_FD)
		return false;

	/* -1UL is the legitimate failure value; handle_failure path. */
	if (rec->retval == -1UL)
		return false;

	s = (long)rec->retval;
	if (s >= 0 && s < (1L << 20))
		return false;

	outputerr("retfd: rejecting out-of-bound retval=0x%lx for %s\n",
		  rec->retval, entry->name);
	post_handler_corrupt_ptr_bump_retfd(rec);
	rec->retval = -1UL;
	rec->errno_post = EINVAL;
	return true;
}

/*
 * Blanket count-bound validator for syscalls whose retval semantics are
 * exactly "bytes/items processed in [0, aN] || -1", driven by the
 * .bound_arg annotation on syscallentry.  Single dispatcher chokepoint
 * means we don't have to sprinkle the same per-syscall .post bound check
 * across every read/write/recv/send-class handler individually -- one
 * gate covers the entire helper-eligible set, and adding a new entry to
 * the set is a one-line .bound_arg = N annotation.
 *
 * Read the count from rec->aN at validator entry rather than from a
 * post_state snapshot: the validator runs before entry->post, so the
 * snap-stash pattern that defends per-syscall post handlers against
 * sibling-stomps of rec->aN is not yet in scope.  Per-syscall .post
 * handlers that already keep a snap-bounded copy (write/listmount/
 * readlink/getcwd etc.) remain in place as a defense-in-depth second
 * layer; this helper catches the symmetric set that has no .post today
 * (read/pread64/recv/sendto/...) for the same logical bug class.
 *
 * Informational only -- do NOT coerce rec->retval.  Unlike the RET_FD
 * blanket validator, an over-large count-bound retval does not seed a
 * downstream wild-write hazard: nobody passes the retval back to the
 * kernel as a buffer length or fd.  The cost of a mis-coerced retval
 * (silently dropping a legitimate large read on a machine whose ulimit
 * raises the bound past the helper's expectation) outweighs the value
 * for a Phase 2 detector.  Coercion is reserved for a follow-up phase
 * once the helper has accumulated quiet-week telemetry.
 *
 * Skip rec->retval == -1UL: failure is the legitimate error path and
 * carries no count semantics.
 */
static void enforce_count_bound(const struct syscallentry *entry,
				struct syscallrecord *rec)
{
	int idx = entry->bound_arg;
	unsigned long count;
	unsigned long ret;

	if (idx == 0)
		return;

	if (rec->retval == -1UL)
		return;

	if (idx < 1 || idx > 6)
		return;

	/* Read via get_arg_snapshot() so a bound_arg slot that opted into
	 * the arg_shadow mask is compared against the dispatch-time value
	 * the kernel actually saw -- a sibling stomping rec->aN between
	 * syscall return and this check would otherwise either fabricate a
	 * spurious "retval exceeds count" warning or hide a real one by
	 * inflating the bound.  Unopted slots fall through the accessor's
	 * mask gate to the live rec->aN, matching the pre-change behaviour. */
	count = get_arg_snapshot(rec, (unsigned int) idx);

	ret = rec->retval;
	if (ret > count) {
		outputerr("count-bound: %s retval=%lu exceeds %s=%lu\n",
			  entry->name, ret,
			  entry->argname[idx - 1] ? entry->argname[idx - 1] : "count",
			  count);
		post_handler_corrupt_ptr_bump_at(rec, NULL,
						 CORRUPT_PTR_SITE_ENFORCE_COUNT_BOUND);
	}
}

/*
 * Table-driven generic return-bound validator.  Complementary to the
 * bespoke rettype gates above (rzs_blanket_reject, reject_corrupt_retfd,
 * enforce_count_bound), this catches the residual RET_* classes whose
 * value range is well-defined by kernel ABI but had no dispatcher-level
 * check.  Entries left .active = false (RET_FD, RET_ADDRESS, the
 * unlisted indices) are skipped: RET_FD is already coerced to -1UL by
 * reject_corrupt_retfd before this runs, so an entry here would be dead;
 * RET_ADDRESS spans the full address space and has no useful generic
 * bound.  RET_ZERO_SUCCESS IS included even though rzs_blanket_reject
 * already bumps a stat counter for it -- the counter is silent, and
 * adding the entry surfaces the per-syscall offender at -v.
 *
 * Informational only -- does not coerce rec->retval.  Skips the universal
 * -1UL error path and any rettype outside [RET_ZERO_SUCCESS, RET_LAST].
 * Logged via output(1, ...) so it stays quiet at the default verbosity
 * and only fires for an operator running with -v.
 */
struct ret_bound {
	long min, max;
	bool active;
};

static const struct ret_bound ret_bounds[RET_LAST + 1] = {
	[RET_ZERO_SUCCESS] = { 0,         0,         true },
	[RET_KEY_SERIAL_T] = { 1,         INT32_MAX, true },
	[RET_PID_T]        = { 0,         4194304,   true },  /* PID_MAX_LIMIT */
	[RET_PATH]         = { 0,         PATH_MAX,  true },
	[RET_NUM_BYTES]    = { 0,         LONG_MAX,  true },  /* ssize_t domain */
	[RET_GID_T]        = { 0,         INT32_MAX, true },
	[RET_UID_T]        = { 0,         INT32_MAX, true },
};

static void validate_ret_bound(const struct syscallentry *entry,
			       struct syscallrecord *rec)
{
	const struct ret_bound *b;
	int rt = effective_rettype(entry, rec);
	long s;

	if (rt <= RET_NONE || rt > RET_LAST)
		return;
	b = &ret_bounds[rt];
	if (!b->active)
		return;
	if (rec->retval == -1UL)
		return;

	s = (long) rec->retval;
	if (s < b->min || s > b->max)
		output(1, "ret-bound: %s rettype=%d retval=%ld outside [%ld, %ld]\n",
		       entry->name, rt, s, b->min, b->max);
}

/*
 * Generic post-hook: register the fd returned by an annotated syscall
 * into its typed OBJ_LOCAL pool.  Runs after entry->post so a
 * syscall-specific handler that already registered the fd (and possibly
 * stored extra metadata like socket triplet, eventfd count, etc.)
 * stays authoritative; we only fill in what nobody else tracked.
 */
static void register_returned_fd(const struct syscallentry *entry,
				 struct syscallrecord *rec)
{
	enum objecttype type = entry->ret_objtype;
	struct object *obj;
	int fd;

	if (type == OBJ_NONE)
		return;
	if ((long)rec->retval < 0)
		return;

	/* Non-fd object kinds (e.g. OBJ_KEY_SERIAL) hand off to a
	 * type-specific registrar — the fd-keyed logic below assumes
	 * an OBJ_FD_* layout (set_object_fd / find_local_object_by_fd
	 * walk fd union members) and would be a no-op otherwise. */
	if (type == OBJ_KEY_SERIAL) {
		long s = (long) rec->retval;

		if (s <= 0 || s > INT32_MAX)
			return;
		register_key_serial((int32_t) s);
		/* Mirror the key serial into the per-child prop_ring so
		 * untyped consumers in gen_undefined_arg can replay it as
		 * input to a later syscall.  prop_ring_push() above
		 * gates OBJ_NONE only, so without this bypass entry the
		 * value would never reach the ring.  Bypass is safe here:
		 * the value already cleared the (0, INT32_MAX] window
		 * register_key_serial requires, and the in-line filters
		 * inside prop_ring_push_scalar still reject pointer-shaped
		 * and fd-aliased values. */
		prop_ring_push_scalar(rec->nr, s, SCALAR_KEY_SERIAL);
		return;
	}

	if (type == OBJ_PID) {
		long p = (long) rec->retval;

		/* fork/vfork/clone parent-side success: a child pid in
		 * [1, PID_MAX_LIMIT=4194304].  Reject 0 (clone child branch
		 * already rerouted by the per-syscall .post handler that
		 * _exit's before reaching here, but defence-in-depth) and
		 * anything past the kernel's pid_max ceiling -- the latter
		 * is the corrupted-retval shape the per-syscall .post oracles
		 * already log via post_handler_corrupt_ptr_bump. */
		if (p <= 0 || p > 4194304)
			return;
		register_returned_pid((pid_t) p);
		return;
	}

	fd = (int)rec->retval;
	if (fd <= 2) {
		__atomic_add_fetch(&shm->stats.fd_runtime.stdio, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	if (find_local_object_by_fd(type, fd) != NULL) {
		__atomic_add_fetch(
			&shm->stats.fd_runtime.already_registered, 1,
			__ATOMIC_RELAXED);
		return;
	}

	obj = alloc_object();
	set_object_fd(obj, type, fd);
	add_object(obj, OBJ_LOCAL, type);

	__atomic_add_fetch(&shm->stats.fd_runtime.registered, 1,
			   __ATOMIC_RELAXED);
}

void do_syscall(struct syscallrecord *rec, struct syscallentry *entry,
		struct kcov_child *kc, struct childdata *child)
{
	/* Arm the self-fuzzed-fatal-signal gate in child_fault_handler.
	 * While set, an own-pid SI_USER/SI_TKILL/SI_QUEUE delivery of
	 * SIGSEGV/SIGBUS/SIGILL/SIGABRT is treated as fuzzer noise (the
	 * child just executed kill/tkill/tgkill/rt_sigqueueinfo/
	 * pidfd_send_signal at itself) and the child exits silently
	 * instead of pouring a bug log into /tmp/.  See signals.c. */
	in_do_syscall = 1;

	if (entry->flags & EXTRA_FORK)
		do_extrafork(rec, entry, child);
	else
		 /* common-case, do the syscall in this child process. */
		__do_syscall(rec, entry, BEFORE, kc, child);

	in_do_syscall = 0;

	/* Reuse the iteration-start timestamp child->tp captured at the top
	 * of random_syscall_step() rather than calling clock_gettime() again.
	 * rec->tp's consumers (taint timestamp ordering in post-mortem, and
	 * pre_crash_ring entry timestamps) only need second-level granularity
	 * for crash attribution — paying for a second clock read per syscall
	 * was pure overhead in the hot path. */
	rec->tp = child->tp;
}

/*
 * If the syscall doesn't exist don't bother calling it next time.
 * Some syscalls return ENOSYS depending on their arguments, we mark
 * those as IGNORE_ENOSYS and keep calling them.
 */
static void deactivate_enosys(struct syscallrecord *rec, struct syscallentry *entry, unsigned int call)
{
	bool did_deactivate = false;

	/* some syscalls return ENOSYS instead of EINVAL etc (futex for eg) */
	if (entry->flags & IGNORE_ENOSYS)
		return;

	lock(&shm->syscalltable_lock);

	/* check another thread didn't already do this. */
	if (entry->active_number != 0) {
		deactivate_syscall_nolock(call, rec->do32bit);
		did_deactivate = true;
	}

	unlock(&shm->syscalltable_lock);

	if (did_deactivate) {
		output(0, "%s (%d%s) returned ENOSYS, marking as inactive.\n",
			entry->name,
			call + SYSCALL_OFFSET,
			rec->do32bit == true ? ":[32BIT]" : "");
		if ((do_specific_syscall || random_selection ||
		     desired_group != GROUP_NONE) &&
		    no_syscalls_enabled() == true)
			outputerr("%s was the last syscall in the targeted "
				  "set; depleted via ENOSYS self-disable\n",
				  entry->name);
	}
}

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

/*
 * Rate-limited (at most once per second per child) WARNING for stale
 * arena-pointer detections.  A single munmap storm from one sibling can
 * fire the probe on many syscalls in quick succession; mirror the
 * canary_stomp_warn_ratelimited cadence so the log stays useful rather
 * than flooding.  Per-process static; the headline counter still
 * accumulates every detection.
 */
static void arena_stale_warn_ratelimited(const struct syscallentry *entry,
					 const char *site, unsigned long v)
{
	static struct timespec last_warn;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (now.tv_sec == last_warn.tv_sec)
		return;
	last_warn = now;

	outputerr("WARNING: arena_ptr_stale caught during %s [%s]: v=0x%lx (page-aligned, in arena band, no live tracker)\n",
		  entry->name, site, v);
}

/*
 * Classify v as live (tracked) / stale (page-aligned arena-band shape
 * with no live tracker) / unknown (out of scope for this probe).
 * Telemetry-only -- callers bump a counter on STALE but do not coerce
 * the slot or skip the post handler.
 *
 * Ordering rationale (matches spec §3):
 *   1. is_corrupt_ptr_shape() -> UNKNOWN: defer to the existing shape
 *      gate; double-firing would double-count the structurally-broken
 *      class under both counters.
 *   2. range_in_tracked_shared() -> LIVE: linear walk of
 *      shared_regions[] + overflow, no LRU window.
 *   3. addr_in_local_runtime_map() -> LIVE: walk of OBJ_LOCAL
 *      OBJ_MMAP_{ANON,FILE,TESTFILE} pools, no LRU window.
 *   4. page-aligned AND inside the literal arena band -> STALE.
 *   5. Anything else -> UNKNOWN (a runtime CHILD_ANON above the band
 *      lands here; out of scope for the literal-band Phase 1).
 */
enum arena_ptr_status {
	ARENA_PTR_LIVE,
	ARENA_PTR_STALE,
	ARENA_PTR_UNKNOWN,
};

static enum arena_ptr_status arena_ptr_liveness(unsigned long v, size_t need)
{
	if (is_corrupt_ptr_shape((const void *) v))
		return ARENA_PTR_UNKNOWN;
	if (range_in_tracked_shared(v, need))
		return ARENA_PTR_LIVE;
	if (addr_in_local_runtime_map(v, need))
		return ARENA_PTR_LIVE;
	if ((v & ((unsigned long) page_size - 1)) == 0 && is_in_arena_band(v))
		return ARENA_PTR_STALE;
	return ARENA_PTR_UNKNOWN;
}

/*
 * Dispatcher-level liveness probe.  Walks the ARG_ADDRESS /
 * ARG_NON_NULL_ADDRESS slots and the rec->post_state tail looking for
 * page-aligned arena-band pointers that no live tracker owns -- the
 * structural shape of the bug 1279961 SEGV at handle_syscall_ret+0x24a
 * (si_addr=0x4037e000) which is_corrupt_ptr_shape() by design admits.
 *
 * Telemetry-only.  Runs AFTER the kernel has returned, so the kernel
 * has already observed whatever value sat in the slot; coercing it now
 * cannot influence the syscall and would itself be a post-dispatch
 * scribble of the shared rec -- exactly the class of bug the wider
 * arg_shadow / canary machinery is meant to surface.  On detection we
 * bump the headline counter, rate-limited warn, and return; downstream
 * consumers must take their own EXPLICIT skip path on a stale slot
 * rather than rely on this probe to coerce.
 */
static void arena_liveness_probe(struct syscallentry *entry,
				 struct syscallrecord *rec)
{
	size_t need = (size_t) page_size;
	unsigned int i;

	for_each_arg(entry, i) {
		enum argtype t = entry->argtype[i - 1];
		unsigned long slot;

		if (t != ARG_ADDRESS && t != ARG_NON_NULL_ADDRESS)
			continue;

		switch (i) {
		case 1: slot = rec->a1; break;
		case 2: slot = rec->a2; break;
		case 3: slot = rec->a3; break;
		case 4: slot = rec->a4; break;
		case 5: slot = rec->a5; break;
		case 6: slot = rec->a6; break;
		default: continue;
		}

		if (arena_ptr_liveness(slot, need) != ARENA_PTR_STALE)
			continue;

		__atomic_add_fetch(&shm->stats.diag.arena_ptr_stale_caught_arg,
				   1, __ATOMIC_RELAXED);
		arena_stale_warn_ratelimited(entry, "arg", slot);
	}

	if (rec->post_state != 0 &&
	    arena_ptr_liveness(rec->post_state, need) == ARENA_PTR_STALE) {
		__atomic_add_fetch(&shm->stats.diag.arena_ptr_stale_caught_post_state,
				   1, __ATOMIC_RELAXED);
		arena_stale_warn_ratelimited(entry, "post_state",
					     rec->post_state);
	}
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
		__atomic_add_fetch(&kcov_shm->per_syscall_errno[call][bucket],
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
			__atomic_store_n(&kcov_shm->last_efault_at[call],
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
				&kcov_shm->errno_bucket_seen[call], bit,
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
