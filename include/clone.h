#pragma once

#include <stdbool.h>
#include <linux/sched.h>

#include "random.h"

#ifndef CLONE_DETACHED
#define CLONE_DETACHED 0x00400000
#endif
#ifndef CLONE_CLEAR_SIGHAND
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif

/*
 * Coerce a random clone-flag bitmask into something the kernel will
 * accept. copy_process() in fork.c rejects a handful of forbidden
 * flag combinations with -EINVAL; without this fix-up the fuzzer
 * burns most of its clone calls on those rejections instead of
 * exercising the actual fork paths.
 *
 * Each rule is resolved with a coin flip between dropping a flag
 * and adding the missing dependent. Both outcomes are valid kernel
 * inputs, so this exercises both sides of every flag check rather
 * than always landing in one branch.
 *
 * @legacy: true for sys_clone(), which packs pidfd and parent_tid
 * into a single user pointer; false for sys_clone3(), which gives
 * each its own field.
 */
static inline void enforce_clone_flag_deps(unsigned long *flags, bool legacy)
{
	/* CLONE_THREAD requires CLONE_SIGHAND. */
	if ((*flags & CLONE_THREAD) && !(*flags & CLONE_SIGHAND)) {
		if (RAND_BOOL())
			*flags |= CLONE_SIGHAND;
		else
			*flags &= ~CLONE_THREAD;
	}

	/*
	 * CLONE_SIGHAND requires CLONE_VM. Dropping CLONE_SIGHAND
	 * forces CLONE_THREAD off too, since THREAD depends on it.
	 */
	if ((*flags & CLONE_SIGHAND) && !(*flags & CLONE_VM)) {
		if (RAND_BOOL())
			*flags |= CLONE_VM;
		else
			*flags &= ~(CLONE_SIGHAND | CLONE_THREAD);
	}

	/* CLONE_NEWNS conflicts with CLONE_FS. */
	if ((*flags & (CLONE_NEWNS | CLONE_FS)) ==
	    (CLONE_NEWNS | CLONE_FS)) {
		if (RAND_BOOL())
			*flags &= ~CLONE_NEWNS;
		else
			*flags &= ~CLONE_FS;
	}

	/* CLONE_NEWUSER conflicts with CLONE_FS. */
	if ((*flags & (CLONE_NEWUSER | CLONE_FS)) ==
	    (CLONE_NEWUSER | CLONE_FS)) {
		if (RAND_BOOL())
			*flags &= ~CLONE_NEWUSER;
		else
			*flags &= ~CLONE_FS;
	}

	/* CLONE_THREAD cannot share with CLONE_NEWUSER. */
	if ((*flags & CLONE_THREAD) && (*flags & CLONE_NEWUSER)) {
		if (RAND_BOOL())
			*flags &= ~CLONE_THREAD;
		else
			*flags &= ~CLONE_NEWUSER;
	}

	/* CLONE_THREAD cannot share with CLONE_NEWPID. */
	if ((*flags & CLONE_THREAD) && (*flags & CLONE_NEWPID)) {
		if (RAND_BOOL())
			*flags &= ~CLONE_THREAD;
		else
			*flags &= ~CLONE_NEWPID;
	}

	/* CLONE_PIDFD conflicts with CLONE_DETACHED. */
	if ((*flags & CLONE_PIDFD) && (*flags & CLONE_DETACHED)) {
		if (RAND_BOOL())
			*flags &= ~CLONE_DETACHED;
		else
			*flags &= ~CLONE_PIDFD;
	}

	/* CLONE_SIGHAND conflicts with CLONE_CLEAR_SIGHAND (clone3). */
	if ((*flags & CLONE_SIGHAND) &&
	    (*flags & CLONE_CLEAR_SIGHAND)) {
		if (RAND_BOOL())
			*flags &= ~CLONE_CLEAR_SIGHAND;
		else
			*flags &= ~CLONE_SIGHAND;
	}

	/*
	 * Legacy sys_clone() aliases pidfd and parent_tid onto a
	 * single user pointer, so the kernel's
	 * args->pidfd == args->parent_tid check fires whenever both
	 * CLONE_PIDFD and CLONE_PARENT_SETTID are set.
	 */
	if (legacy &&
	    (*flags & CLONE_PIDFD) &&
	    (*flags & CLONE_PARENT_SETTID)) {
		if (RAND_BOOL())
			*flags &= ~CLONE_PIDFD;
		else
			*flags &= ~CLONE_PARENT_SETTID;
	}
}
