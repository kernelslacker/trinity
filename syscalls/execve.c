/*
 * SYSCALL_DEFINE3(execve,
 *                const char __user *, filename,
 *                const char __user *const __user *, argv,
 *                const char __user *const __user *, envp)
 *
 * On success, execve() does not return
 * on error -1 is returned, and errno is set appropriately.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "arch.h"	// page_size
#include "random.h"	// generate_rand_bytes
#include "sanitise.h"
#include "shm.h"
#include "tables.h"
#include "trinity.h"	// __unused__
#include "utils.h"
#include "compat.h"

static unsigned long ** gen_ptrs_to_crap(unsigned int count)
{
	void **ptr;
	unsigned int i;

	/* Fabricate argv */
	ptr = zmalloc(count * sizeof(void *));

	for (i = 0; i < count; i++) {
		ptr[i] = zmalloc(page_size);
		generate_rand_bytes((unsigned char *) ptr[i], rand() % page_size);
	}

	return (unsigned long **) ptr;
}

/*
 * Redirect stdin/stdout/stderr before execve so the new process
 * can't block on reads or corrupt the fuzzer's output.
 *
 * stdin  <- /dev/null (prevents blocking reads)
 * stdout -> /dev/null (prevents output corruption)
 * stderr -> /dev/null (prevents output corruption)
 *
 * If the redirects fail we press on anyway — execve will almost
 * certainly fail with our random argv, and the child exits either way.
 */
static void redirect_stdio(void)
{
	int devnull;

	devnull = open("/dev/null", O_RDWR);
	if (devnull == -1)
		return;

	(void) dup2(devnull, STDIN_FILENO);
	(void) dup2(devnull, STDOUT_FILENO);
	(void) dup2(devnull, STDERR_FILENO);

	if (devnull > STDERR_FILENO)
		close(devnull);
}

static void sanitise_execve(struct syscallrecord *rec)
{
	unsigned long **argv, **envp;
	unsigned int argvcount, envpcount;

	redirect_stdio();

	/* Fabricate argv */
	argvcount = rand() % 32;
	argv = gen_ptrs_to_crap(argvcount);

	/* Fabricate envp */
	envpcount = rand() % 32;
	envp = gen_ptrs_to_crap(envpcount);

	/* Pack both counts into a6 (unused by both execve and execveat). */
	rec->a6 = ((unsigned long)argvcount << 32) | envpcount;

	if (this_syscallname("execve") == true) {
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

static void free_execve_ptrs(void **argv, void **envp,
			      unsigned int argvcount, unsigned int envpcount)
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
	void **argv = (void **) rec->a2;
	void **envp = (void **) rec->a3;

	/*
	 * free_execve_ptrs() walks argv[]/envp[] then free()s the outer
	 * arrays.  A pid-scribble in either rec->a2 or rec->a3 makes the
	 * inner walk crash on the first deref.  Cluster-1/2/3 guard.
	 */
	if (looks_like_corrupted_ptr(argv) || looks_like_corrupted_ptr(envp)) {
		outputerr("post_execve: rejected suspicious argv=%p envp=%p "
			  "(pid-scribbled?)\n", argv, envp);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		return;
	}
	free_execve_ptrs(argv, envp,
			 (unsigned int)(rec->a6 >> 32),
			 (unsigned int)(rec->a6 & 0xFFFFFFFF));
}

static void post_execveat(struct syscallrecord *rec)
{
	void **argv = (void **) rec->a3;
	void **envp = (void **) rec->a4;

	if (looks_like_corrupted_ptr(argv) || looks_like_corrupted_ptr(envp)) {
		outputerr("post_execveat: rejected suspicious argv=%p envp=%p "
			  "(pid-scribbled?)\n", argv, envp);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		return;
	}
	free_execve_ptrs(argv, envp,
			 (unsigned int)(rec->a6 >> 32),
			 (unsigned int)(rec->a6 & 0xFFFFFFFF));
}

struct syscallentry syscall_execve = {
	.name = "execve",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "name", [1] = "argv", [2] = "envp" },
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
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "name", [2] = "argv", [3] = "envp", [4] = "flags" },
	.arg_params[4].list = ARGLIST(execveat_flags),
	.sanitise = sanitise_execve,
	.post = post_execveat,
	.group = GROUP_VFS,
	.flags = EXTRA_FORK,
};
