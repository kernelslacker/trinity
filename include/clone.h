#pragma once

#include <linux/sched.h>

/*
 * Enforce mandatory flag dependencies from the kernel:
 *   CLONE_THREAD requires CLONE_SIGHAND
 *   CLONE_SIGHAND requires CLONE_VM
 */
static inline void enforce_clone_flag_deps(unsigned long *flags)
{
	if (*flags & CLONE_THREAD)
		*flags |= CLONE_SIGHAND;
	if (*flags & CLONE_SIGHAND)
		*flags |= CLONE_VM;
}
