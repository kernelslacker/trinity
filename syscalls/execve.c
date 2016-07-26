/*
 * SYSCALL_DEFINE3(execve,
 *                const char __user *, filename,
 *                const char __user *const __user *, argv,
 *                const char __user *const __user *, envp)
 *
 * On success, execve() does not return
 * on error -1 is returned, and errno is set appropriately.
 *
 * TODO: Redirect stdin/stdout.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "arch.h"	// page_size
#include "random.h"	// generate_rand_bytes
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"	// __unused__
#include "utils.h"
#include "compat.h"

static unsigned int argvcount;
static unsigned int envpcount;

static unsigned long ** gen_ptrs_to_crap(unsigned int count)
{
	void **ptr;
	unsigned int i;

	/* Fabricate argv */
	ptr = zmalloc(count * sizeof(void *));

	for (i = 0; i < count; i++) {
		ptr[i] = zmalloc(page_size);
		generate_rand_bytes((unsigned char *) ptr[i], rnd() % page_size);
	}

	return (unsigned long **) ptr;
}

static void sanitise_execve(struct syscallrecord *rec)
{
	unsigned long **argv, **envp;

	/* we don't want to block if something tries to read from stdin */
	fclose(stdin);

	/* Fabricate argv */
	argvcount = rnd() % 32;
	argv = gen_ptrs_to_crap(argvcount);

	/* Fabricate envp */
	envpcount = rnd() % 32;
	envp = gen_ptrs_to_crap(envpcount);

	if (this_syscallname("execve") == FALSE) {
		rec->a2 = (unsigned long) argv;
		rec->a3 = (unsigned long) envp;
	} else {
		rec->a3 = (unsigned long) argv;
		rec->a4 = (unsigned long) envp;
	}
}

/* if execve succeeds, we'll never get back here, so this only
 * has to worry about the case where execve returned a failure.
 */

static void free_execve_ptrs(void **argv, void **envp)
{
	unsigned int i;

	for (i = 0; i < argvcount; i++)
		free(argv[i]);
	free(argv);

	for (i = 0; i < envpcount; i++)
		free(envp[i]);
	free(envp);
}

static void post_execve(struct syscallrecord *rec)
{
	free_execve_ptrs((void **) rec->a2, (void **) rec->a3);
}

static void post_execveat(struct syscallrecord *rec)
{
	free_execve_ptrs((void **) rec->a3, (void **) rec->a4);
}

struct syscallentry syscall_execve = {
	.name = "execve",
	.num_args = 3,
	.arg1name = "name",
	.arg1type = ARG_PATHNAME,
	.arg2name = "argv",
	.arg2type = ARG_ADDRESS,
	.arg3name = "envp",
	.arg3type = ARG_ADDRESS,
	.sanitise = sanitise_execve,
	.post = post_execve,
	.group = GROUP_VFS,
	.flags = EXTRA_FORK,
};

static unsigned long execveat_flags[] = {
	AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW,
};

struct syscallentry syscall_execveat = {
	.name = "execveat",
	.num_args = 5,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "name",
	.arg2type = ARG_PATHNAME,
	.arg3name = "argv",
	.arg3type = ARG_ADDRESS,
	.arg4name = "envp",
	.arg4type = ARG_ADDRESS,
	.arg5name = "flags",
	.arg5type = ARG_LIST,
	.arg5list = ARGLIST(execveat_flags),
	.sanitise = sanitise_execve,
	.post = post_execveat,
	.group = GROUP_VFS,
	.flags = EXTRA_FORK,
};
