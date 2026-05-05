/*
 * Functions for actually doing the system calls.
 */

#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "arch.h"
#include "child.h"
#include "debug.h"
#include "deferred-free.h"
#include "kcov.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "results.h"
#include "sanitise.h"
#include "shm.h"
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

				if (entry->active_number != 0)
					deactivate_syscall(i, true);
			}
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

static void __do_syscall(struct syscallrecord *rec, struct syscallentry *entry,
			 enum syscallstate state,
			 struct kcov_child *kc, struct childdata *child)
{
	unsigned long ret = dry_run ? -1UL : 0;
	bool fault_armed = false;

	errno = 0;

	/* Bump our per-child counter; flush to the shared atomic in batches
	 * so we don't bounce shm->stats.op_count's cache line on every call. */
	if (child != NULL) {
		child->local_op_count++;
		if (child->local_op_count >= LOCAL_OP_FLUSH_BATCH) {
			__atomic_add_fetch(&shm->stats.op_count,
					   child->local_op_count, __ATOMIC_RELAXED);
			child->local_op_count = 0;
		}
	} else {
		__atomic_add_fetch(&shm->stats.op_count, 1, __ATOMIC_RELAXED);
	}

	if (dry_run == false) {
		int call;
		bool needalarm;

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

		/* Arm the alarm after releasing rec->lock.  Previously
		 * alarm(1) was above the lock region, creating a window
		 * where SIGALRM could fire while we held the lock.  The
		 * siglongjmp in the handler would then orphan it. */
		if (needalarm)
			(void)alarm(1);

		if (rec->do32bit == false) {
			if (kc != NULL && kc->remote_mode)
				kcov_enable_remote(kc);
			else if (kc != NULL && kc->cmp_mode)
				kcov_enable_cmp(kc);
			else
				kcov_enable_trace(kc);
			fault_armed = maybe_inject_fault(child, state);
			ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6);
			kcov_disable(kc);
		} else {
			if (kc != NULL && kc->remote_mode)
				kcov_enable_remote(kc);
			else if (kc != NULL && kc->cmp_mode)
				kcov_enable_cmp(kc);
			else
				kcov_enable_trace(kc);
			fault_armed = maybe_inject_fault(child, state);
			ret = syscall32(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6);
			kcov_disable(kc);
		}

		/* fail-nth resets to 0 in the kernel after the syscall completes.
		 * Tally whether the armed fault actually triggered (-ENOMEM) vs
		 * went unconsumed (the syscall didn't reach an allocation we hit). */
		if (fault_armed) {
			__atomic_add_fetch(&shm->stats.fault_injected, 1, __ATOMIC_RELAXED);
			if (ret == (unsigned long)-1L && errno == ENOMEM)
				__atomic_add_fetch(&shm->stats.fault_consumed, 1, __ATOMIC_RELAXED);
		}

		/* If we became tainted, get out as fast as we can. */
		if (is_tainted() == true) {
			panic(EXIT_KERNEL_TAINTED);
			_exit(EXIT_KERNEL_TAINTED);
		}

		if (needalarm)
			(void)alarm(0);
	}

	lock(&rec->lock);
	rec->errno_post = errno;
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
		usleep(1000);
	}

	/* Timed out. Force-kill and reap to prevent zombies. */
	if (pid == 0) {
		kill(extrapid, SIGKILL);
		waitpid(extrapid, NULL, 0);
	}
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
 * via the rec it's passed.
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
	post_handler_corrupt_ptr_bump(rec, NULL);
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

	fd = (int)rec->retval;
	if (fd <= 2)
		return;

	if (find_local_object_by_fd(type, fd) != NULL)
		return;

	obj = alloc_object();
	set_object_fd(obj, type, fd);
	add_object(obj, OBJ_LOCAL, type);

	__atomic_add_fetch(&shm->stats.fd_runtime_registered, 1,
			   __ATOMIC_RELAXED);
}

void do_syscall(struct syscallrecord *rec, struct syscallentry *entry,
		struct kcov_child *kc, struct childdata *child)
{
	if (entry->flags & EXTRA_FORK)
		do_extrafork(rec, entry, child);
	else
		 /* common-case, do the syscall in this child process. */
		__do_syscall(rec, entry, BEFORE, kc, child);

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

	output(1, "%s (%d%s) returned ENOSYS, marking as inactive.\n",
		entry->name,
		call + SYSCALL_OFFSET,
		rec->do32bit == true ? ":[32BIT]" : "");

	deactivate_syscall(call, rec->do32bit);
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
	 * still run since the sub-attribution ring needs the .post PC.
	 * Sub-attribution lands in post_handler_corrupt_ptr's per-handler
	 * ring under the (nr, do32bit) of the offending syscall. */
	if (unlikely(rec->rettype == RET_ZERO_SUCCESS &&
		     rec->retval != 0 && rec->retval != -1UL)) {
		__atomic_add_fetch(&shm->stats.rzs_blanket_reject, 1,
				   __ATOMIC_RELAXED);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

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
			if (err < NR_ERRNOS) {
				__atomic_add_fetch(&entry->errnos[err], 1, __ATOMIC_RELAXED);
			} else {
				// "These should never be seen by user programs."
				// But trinity isn't a 'normal' user program, we're doing
				// stuff that libc hides from apps.
				if (err < 512 || err > 530)
					outputerr("errno out of range after doing %s: %d:%s\n",
						entry->name,
						err, strerror(err));
			}
			__atomic_add_fetch(&shm->stats.failures, 1, __ATOMIC_RELAXED);
		}
	} else {
		handle_success(rec);	// Believe me folks, you'll never get bored with winning
		__atomic_add_fetch(&entry->successes, 1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.successes, 1, __ATOMIC_RELAXED);
	}
	__atomic_add_fetch(&entry->attempted, 1, __ATOMIC_RELAXED);

	reject_corrupt_retfd(entry, rec);

	enforce_count_bound(entry, rec);

	if (entry->post)
	    entry->post(rec);

	register_returned_fd(entry, rec);

	check_uid();

	generic_free_arg(rec);
}
