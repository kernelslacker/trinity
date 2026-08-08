/*
 * Raw syscall execution path carved out of dispatch/syscall.c:
 * biarch 32-on-64 dispatch, fail-nth fault injection, in-child
 * watchdog fd eviction, SHADOW noisy-sample bracket, the __do_syscall
 * bracket itself, and the do_extrafork throwaway-grandchild wrapper
 * for EXTRA_FORK syscalls.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"
#include "arg_coupling.h"
#include "argtype-ops.h"
#include "child.h"
#include "fd-event.h"
#include "fd.h"
#include "kcov.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "signals.h"
#include "stats_ring.h"
#include "syscall.h"
#include "syscall-internal.h"
#include "syscall_record.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
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

					if (syscall_rt(entry)->active_number != 0)
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

void __do_syscall(struct syscallrecord *rec, struct syscallentry *entry,
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
		clear_stale_kcov_state(kc, rec);  /* header zero + dispatch_args_valid clear */
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
		clear_stale_kcov_state(kc, rec);  /* header zero + dispatch_args_valid clear */
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
	 * hints.  At most one fd is enabled per syscall because the kernel's
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

	/* Mark kernel entry committed.  Both early-return paths above
	 * (validate_arg_coupling reject and --dry-run) return before
	 * this point, so kernel_entered is false on those paths and
	 * true only when syscall() is about to be invoked. */
	rec->kernel_entered = true;

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
	{
		struct timespec _tc0, _tc1;
		bool _tainted;
		long _ns;

		clock_gettime(CLOCK_MONOTONIC, &_tc0);
		_tainted = is_tainted();
		clock_gettime(CLOCK_MONOTONIC, &_tc1);
		_ns = (_tc1.tv_sec - _tc0.tv_sec) * 1000000000L
		      + (_tc1.tv_nsec - _tc0.tv_nsec);
		__atomic_add_fetch(&shm->stats.diag.taint_check_calls,
				   1, __ATOMIC_RELAXED);
		if (_ns > 0)
			__atomic_add_fetch(&shm->stats.diag.taint_check_ns,
					   (unsigned long)_ns,
					   __ATOMIC_RELAXED);
		if (_tainted) {
			panic(EXIT_KERNEL_TAINTED);
			_exit(EXIT_KERNEL_TAINTED);
		}
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
void do_extrafork(struct syscallrecord *rec, struct syscallentry *entry,
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

	/* Timed out, or waitpid errored. Force-kill, then try a bounded
	 * WNOHANG reap. A D-state grandchild survives SIGKILL, and a
	 * blocking waitpid here would pin the worker past the ~1s budget
	 * claimed above. If the grandchild still hasn't exited after a
	 * few short polls, log and continue -- leave it as a zombie for
	 * the eventual SIGCHLD path rather than wedging the worker.
	 */
	if (pid <= 0) {
		pid_t rp = 0;

		kill(extrapid, SIGKILL);
		for (int i = 0; i < 5; i++) {
			rp = waitpid_eintr(extrapid, NULL, WNOHANG);
			if (rp != 0)
				break;
			usleep(1000);
		}
		if (rp == 0)
			output(1, "extrafork: grandchild %d unreapable after SIGKILL, leaving zombie\n",
			       extrapid);
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
