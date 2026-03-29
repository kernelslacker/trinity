/*
 * SYSCALL_DEFINE2(clone3, struct clone_args __user *, uargs, size_t, size)
 */

#include <stdlib.h>
#include <signal.h>
#include <linux/sched.h>
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"
#include "compat.h"

#ifndef CLONE_ARGS_SIZE_VER0
#define CLONE_ARGS_SIZE_VER0 64
#endif
#ifndef CLONE_ARGS_SIZE_VER1
#define CLONE_ARGS_SIZE_VER1 80
#endif
#ifndef CLONE_ARGS_SIZE_VER2
#define CLONE_ARGS_SIZE_VER2 88
#endif

static unsigned long clone3_flags[] = {
	CLONE_VM, CLONE_FS, CLONE_FILES, CLONE_SIGHAND,
	CLONE_PIDFD, CLONE_PTRACE, CLONE_VFORK, CLONE_PARENT,
	CLONE_THREAD, CLONE_NEWNS, CLONE_SYSVSEM, CLONE_SETTLS,
	CLONE_PARENT_SETTID, CLONE_CHILD_CLEARTID, CLONE_UNTRACED,
	CLONE_CHILD_SETTID, CLONE_NEWCGROUP, CLONE_NEWUTS,
	CLONE_NEWIPC, CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET,
	CLONE_IO, CLONE_NEWTIME,
};

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

static unsigned long clone3_sizes[] = {
	CLONE_ARGS_SIZE_VER0,
	CLONE_ARGS_SIZE_VER1,
	CLONE_ARGS_SIZE_VER2,
	sizeof(struct clone_args),
};

static void sanitise_clone3(struct syscallrecord *rec)
{
	struct clone_args *args;

	args = zmalloc(sizeof(struct clone_args));

	args->flags = set_rand_bitmask(ARRAY_SIZE(clone3_flags), clone3_flags);
	if (args->flags & CLONE_THREAD)
		args->flags |= CLONE_SIGHAND;
	if (args->flags & CLONE_SIGHAND)
		args->flags |= CLONE_VM;
	args->exit_signal = rand() % _NSIG;

	rec->a1 = (unsigned long) args;
	rec->a2 = RAND_ARRAY(clone3_sizes);
}

static void post_clone3(struct syscallrecord *rec)
{
	freeptr(&rec->a1);
}

struct syscallentry syscall_clone3 = {
	.name = "clone3",
	.group = GROUP_PROCESS,
	.num_args = 2,
	.flags = AVOID_SYSCALL,
	.argname = { [0] = "uargs", [1] = "size" },
	.sanitise = sanitise_clone3,
	.post = post_clone3,
	.rettype = RET_PID_T,
};
