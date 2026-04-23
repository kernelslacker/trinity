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

static void __do_syscall(struct syscallrecord *rec, enum syscallstate state,
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
		int nr, call;
		bool needalarm;
		struct syscallentry *entry;

		nr = rec->nr;
		call = nr + SYSCALL_OFFSET;
		entry = get_syscall_entry(nr, rec->do32bit);
		BUG_ON(entry == NULL);
		needalarm = entry->flags & NEED_ALARM;

		lock(&rec->lock);
		rec->state = state;
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
static void do_extrafork(struct syscallrecord *rec, struct childdata *child)
{
	pid_t pid = 0;
	pid_t extrapid;

	extrapid = fork();
	if (extrapid == 0) {
		/* grand-child */
		char childname[]="trinity-subchild";
		prctl(PR_SET_NAME, (unsigned long) &childname);

		__do_syscall(rec, GOING_AWAY, NULL, child);
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
	if ((long)rec->retval >= 0)
		close((int)rec->retval);
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

void do_syscall(struct syscallrecord *rec, struct kcov_child *kc, struct childdata *child)
{
	struct syscallentry *entry;
	unsigned int call;

	call = rec->nr;
	entry = get_syscall_entry(call, rec->do32bit);
	BUG_ON(entry == NULL);

	if (entry->flags & EXTRA_FORK)
		do_extrafork(rec, child);
	else
		 /* common-case, do the syscall in this child process. */
		__do_syscall(rec, BEFORE, kc, child);

	/* timestamp again for when we returned */
	clock_gettime(CLOCK_MONOTONIC, &rec->tp);
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

void handle_syscall_ret(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int call;

	call = rec->nr;
	entry = syscalls[call].entry;

	if (rec->retval == -1UL) {
		int err = rec->errno_post;

		/* For EXTRA_FORK syscalls (e.g. execve), the grandchild runs
		 * with state GOING_AWAY and may die or get killed before
		 * setting state to AFTER.  Only process the result if the
		 * syscall actually completed. */
		if (rec->state == AFTER) {
			if (err == ENOSYS)
				deactivate_enosys(rec, entry, call);

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

	if (entry->post)
	    entry->post(rec);

	register_returned_fd(entry, rec);

	check_uid();

	generic_free_arg(rec);
}
