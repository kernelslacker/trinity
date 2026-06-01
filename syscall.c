/*
 * Functions for actually doing the system calls.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "arch.h"
#include "arg_coupling.h"
#include "child.h"
#include "debug.h"
#include "deferred-free.h"
#include "fd-event.h"
#include "fd.h"
#include "kcov.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "results.h"
#include "sanitise.h"
#include "shm.h"
#include "signals.h"
#include "stats_ring.h"
#include "syscall.h"
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

			lock(&shm->syscalltable_lock);

			/* check another thread didn't already do this. */
			if (shm->nr_active_32bit_syscalls == 0)
				goto already_done;

			output(0, "Tried %d 32-bit syscalls unsuccessfully. Disabling all 32-bit syscalls.\n",
					__atomic_load_n(&shm->syscalls32_attempted, __ATOMIC_RELAXED));

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
already_done:
			unlock(&shm->syscalltable_lock);
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

	lock(&rec->lock);
	rec->state = state;
	/* Stamp the wholesale-stomp canary just before dispatch so
	 * handle_syscall_ret() can tell whether anything overwrote
	 * the rec while the kernel had control.  One store on the hot
	 * path; the matching load is paired with the AFTER snapshot
	 * read inside the post handler. */
	rec->_canary = REC_CANARY_MAGIC;
	unlock(&rec->lock);

	/* Second blanket_address_scrub() pass, post-unlock and pre-snapshot:
	 * closes the sibling-stomp window between the sanitise-time scrub at
	 * the tail of generate_syscall_args() and the local snapshot below.
	 * Same range-aware predicate and same address_scrub_mask (honouring
	 * SKIP_BLANKET_SCRUB) as the first pass — only the timing moves. */
	blanket_address_scrub(entry, rec);

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

	/* Cross-arg consistency check: catch (buf_ptr, count) pairs the
	 * kernel would reject at its earliest validation step so we
	 * don't burn a syscall round-trip and a kcov enable/disable on
	 * a call that can't exercise an interesting path.  On rejection
	 * synthesize a -1/EINVAL AFTER state so handle_syscall_ret()
	 * accounts the rejection identically to a real early-EINVAL
	 * failure (no separate stats infrastructure to maintain).  Zero
	 * the kcov trace count header manually because kcov_enable_trace
	 * (which usually owns that zeroing) never runs on the skip path
	 * and the caller's kcov_collect() would otherwise re-process the
	 * previous syscall's PCs against this slot. */
	if (validate_arg_coupling(rec) != 0) {
		post_handler_corrupt_ptr_bump(rec, NULL);
		if (kc != NULL && kc->active) {
			if (kc->mode == KCOV_MODE_PC && kc->trace_buf != NULL)
				__atomic_store_n(&kc->trace_buf[0], 0,
						 __ATOMIC_RELAXED);
			else if (kc->mode == KCOV_MODE_CMP &&
				 kc->cmp_trace_buf != NULL)
				__atomic_store_n(&kc->cmp_trace_buf[0], 0,
						 __ATOMIC_RELAXED);
		}
		lock(&rec->lock);
		rec->errno_post = EINVAL;
		rec->retval = (unsigned long) -1L;
		rec->validator_rejected = true;
		rec->state = AFTER;
		unlock(&rec->lock);
		return;
	}

	/* Arm the alarm after releasing rec->lock.  Previously
	 * alarm(1) was above the lock region, creating a window
	 * where SIGALRM could fire while we held the lock.  The
	 * siglongjmp in the handler would then orphan it. */
	if (needalarm)
		(void)alarm(1);

	/* Per-child mode picked once in kcov_init_child: PC-mode children
	 * enable the PC fd (per-thread or remote) and feed edge coverage,
	 * CMP-mode children enable the cmp fd and feed comparison-operand
	 * hints.  Exactly one fd is enabled per syscall because the kernel's
	 * one-`t->kcov`-per-task rule returns -EBUSY on a second simultaneous
	 * enable; the fleet-wide PC/CMP signal split comes from the
	 * population mix instead of per-call mode toggling. */
	if (rec->do32bit == false) {
		if (kc != NULL && kc->mode == KCOV_MODE_CMP) {
			kcov_enable_cmp(kc);
		} else if (kc != NULL && kc->remote_mode) {
			kcov_enable_remote(kc, child != NULL ? child->num : 0);
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
			kcov_enable_remote(kc, child != NULL ? child->num : 0);
		} else {
			kcov_enable_trace(kc);
		}
		fault_armed = maybe_inject_fault(child, state);
		ret = syscall32(call, a1, a2, a3, a4, a5, a6);
		saved_errno = errno;
		kcov_disable(kc);
	}

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

	lock(&rec->lock);
	rec->errno_post = saved_errno;
	rec->retval = ret;
	rec->state = AFTER;
	unlock(&rec->lock);
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

	extrapid = fork();
	if (extrapid == 0) {
		/* grand-child */
		char childname[]="trinity-subchild";
		prctl(PR_SET_NAME, (unsigned long) &childname);

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
		return;
	}

	/* small pause to let grandchild do some work. */
	if (pid_alive(extrapid) == true)
		usleep(100);

	/* Do NOT hold rec->lock here. The grandchild acquires it inside
	 * __do_syscall(), so holding it while waiting would deadlock:
	 * parent holds lock -> waitpid(grandchild) -> grandchild spins
	 * on same lock -> neither can make progress.
	 *
	 * Bound the loop to ~1 second (1000 * 1ms) so a D-state
	 * grandchild can't stall us forever.
	 */
	for (int i = 0; pid == 0 && i < 1000; i++) {
		int childstatus;

		pid = waitpid(extrapid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		if (pid < 0 && errno == EINTR)
			pid = 0;	/* transient, keep retrying within the budget */
		usleep(1000);
	}

	/* Timed out, or waitpid errored. Force-kill and reap to prevent zombies. */
	if (pid <= 0) {
		kill(extrapid, SIGKILL);
		waitpid(extrapid, NULL, 0);
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
	if (rec->state != AFTER && entry->post != NULL)
		entry->post(rec);
}


void generic_post_close_fd(struct syscallrecord *rec)
{
	long ret = (long)rec->retval;
	if (ret >= 0 && ret < (1 << 20))
		close((int)ret);
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
 * Read rec->rettype rather than entry->rettype: fcntl(F_DUPFD /
 * F_DUPFD_CLOEXEC) and futex(FUTEX_FD) only set RET_FD on the rec at
 * sanitise time; their syscallentries advertise something else.
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

	if (rec->rettype != RET_FD)
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

	switch (idx) {
	case 1: count = rec->a1; break;
	case 2: count = rec->a2; break;
	case 3: count = rec->a3; break;
	case 4: count = rec->a4; break;
	case 5: count = rec->a5; break;
	case 6: count = rec->a6; break;
	default: return;
	}

	ret = rec->retval;
	if (ret > count) {
		outputerr("count-bound: %s retval=%lu exceeds %s=%lu\n",
			  entry->name, ret,
			  entry->argname[idx - 1] ? entry->argname[idx - 1] : "count",
			  count);
		post_handler_corrupt_ptr_bump(rec, NULL);
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
	int rt = rec->rettype;
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
		__atomic_add_fetch(&shm->stats.fd_runtime_skipped_stdio, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	if (find_local_object_by_fd(type, fd) != NULL) {
		__atomic_add_fetch(
			&shm->stats.fd_runtime_skipped_already_registered, 1,
			__ATOMIC_RELAXED);
		return;
	}

	obj = alloc_object();
	set_object_fd(obj, type, fd);
	add_object(obj, OBJ_LOCAL, type);

	__atomic_add_fetch(&shm->stats.fd_runtime_registered, 1,
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
	/* some syscalls return ENOSYS instead of EINVAL etc (futex for eg) */
	if (entry->flags & IGNORE_ENOSYS)
		return;

	lock(&shm->syscalltable_lock);

	/* check another thread didn't already do this. */
	if (entry->active_number == 0)
		goto already_done;

	output(0, "%s (%d%s) returned ENOSYS, marking as inactive.\n",
		entry->name,
		call + SYSCALL_OFFSET,
		rec->do32bit == true ? ":[32BIT]" : "");

	deactivate_syscall_nolock(call, rec->do32bit);
already_done:
	unlock(&shm->syscalltable_lock);
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

void handle_syscall_ret(struct syscallrecord *rec, struct syscallentry *entry)
{
	unsigned int call = rec->nr;
	bool retfd_rejected;

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
			__atomic_add_fetch(&shm->stats.rec_canary_stomped, 1,
					   __ATOMIC_RELAXED);
			pre_crash_ring_record_canary(this_child(), rec, observed);
			canary_stomp_warn_ratelimited(entry, observed);
			/* Restamp so a second post-handler invocation on the
			 * same rec (none today, but cheap insurance) doesn't
			 * re-fire on the stale mismatch. */
			rec->_canary = REC_CANARY_MAGIC;
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
	 * Use rec->rettype, not entry->rettype, so per-cmd overrides apply
	 * to the correct subset of calls.  Informational like the canary
	 * check above; downstream success/failure tally and entry->post
	 * still run.  rzs_blanket_reject is the only counter touched here:
	 * this is a dispatcher-level rettype-contract violation (a sibling
	 * scribbled rec->retval after the syscall returned), distinct from
	 * a .post handler rejecting a pid-shaped pointer in rec->aN.  The
	 * two bug classes used to share post_handler_corrupt_ptr, which
	 * inflated the headline counter and smeared the per-handler
	 * attribution; they are accounted separately now. */
	if (unlikely(rec->rettype == RET_ZERO_SUCCESS &&
		     rec->retval != 0 && rec->retval != -1UL))
		__atomic_add_fetch(&shm->stats.rzs_blanket_reject, 1,
				   __ATOMIC_RELAXED);

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
	retfd_rejected = reject_corrupt_retfd(entry, rec);
	if (retfd_rejected)
		__atomic_add_fetch(&shm->stats.retfd_blanket_reject, 1,
				   __ATOMIC_RELAXED);

	if (rec->retval == -1UL) {
		int err = rec->errno_post;

		/* For EXTRA_FORK syscalls (e.g. execve), the grandchild runs
		 * with state GOING_AWAY and may die or get killed before
		 * setting state to AFTER.  Only process the result if the
		 * syscall actually completed. */
		if (rec->state == AFTER) {
			if (err == ENOSYS)
				deactivate_enosys(rec, entry, call);

			handle_failure(rec);
			__atomic_add_fetch(&entry->failures, 1, __ATOMIC_RELAXED);
			if (err >= 0 && err < NR_ERRNOS) {
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
	} else if (rec->state == AFTER) {
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
	if (rec->state == AFTER && kcov_shm != NULL && call < MAX_NR_SYSCALL) {
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

		/* Stamp last_efault_at[] with the current total_calls so a
		 * future picker pass can bias away from syscalls stuck in
		 * pure-EFAULT regimes.  total_calls is the same counter
		 * last_edge_at[] uses, so the two fields stay directly
		 * comparable. */
		if (bucket == ERRNO_BUCKET_EFAULT) {
			unsigned long now_call =
				__atomic_load_n(&kcov_shm->total_calls,
						__ATOMIC_RELAXED);
			__atomic_store_n(&kcov_shm->last_efault_at[call],
					 now_call, __ATOMIC_RELAXED);
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
	if (rec->state == AFTER) {
		enforce_count_bound(entry, rec);
		validate_ret_bound(entry, rec);

		/* Post-derived secondary-object registrar runs ahead of
		 * entry->post: per-syscall .post handlers (pipe,
		 * socketpair, io_setup, timer_create) clear rec->post_state
		 * as part of their cleanup pass, and the hook reads
		 * post_state / rec->aN to derive what to register.  Same
		 * retfd-rejected gate as entry->post -- a fabricated
		 * retval shouldn't drive any registration. */
		if (entry->ret_objtype_via_post && !retfd_rejected)
			entry->ret_objtype_via_post(rec);

		/* Skip entry->post on a rejected RET_FD: handler would
		 * be acting on a fabricated retval, attribution already
		 * happened inside reject_corrupt_retfd().
		 * register_returned_fd() below already short-circuits on
		 * (long)rec->retval < 0 so the coerced -1UL makes it a
		 * no-op there regardless. */
		if (entry->post && !retfd_rejected)
		    entry->post(rec);

		register_returned_fd(entry, rec);
	}

	/* check_uid inspects current process state, not rec; safe to
	 * run regardless.  generic_free_arg frees ARG_PATHNAME /
	 * ARG_IOVEC / ARG_SOCKADDR buffers that the parent allocated
	 * before do_syscall ran -- they exist independent of whether
	 * the grandchild reached AFTER and MUST be freed to avoid
	 * leaking. */
	check_uid();

	generic_free_arg(entry, rec);
}
