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
#include "deferred-free.h"
#include "random.h"	// generate_rand_bytes
#include "sanitise.h"
#include "shm.h"
#include "tables.h"
#include "trinity.h"	// __unused__
#include "utils.h"
#include "compat.h"

/*
 * Snapshot of the argv/envp arrays and their lengths, captured at sanitise
 * time and consumed by the post handler.  Lives in rec->post_state, a slot
 * the syscall ABI does not expose, so the post-time array walk operates on
 * values immune to a sibling syscall scribbling rec->a2/a3/a4 between the
 * syscall returning and the post handler running.
 */
struct execve_post_state {
	void **argv;
	void **envp;
	unsigned long argvcount;
	unsigned long envpcount;
};

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
	struct execve_post_state *snap;
	unsigned long **argv, **envp;
	unsigned int argvcount, envpcount;

	redirect_stdio();

	/* Fabricate argv */
	argvcount = rand() % 32;
	argv = gen_ptrs_to_crap(argvcount);

	/* Fabricate envp */
	envpcount = rand() % 32;
	envp = gen_ptrs_to_crap(envpcount);

	if (this_syscallname("execve") == true) {
		rec->a2 = (unsigned long) argv;
		rec->a3 = (unsigned long) envp;
	} else {
		rec->a3 = (unsigned long) argv;
		rec->a4 = (unsigned long) envp;
	}

	/*
	 * Snapshot the array pointers and counts for the post handler.  The
	 * snapshot lives in rec->post_state, which the syscall ABI does not
	 * expose, so a sibling syscall scribbling rec->a2/a3/a4 between the
	 * syscall returning and the post handler running cannot misdirect
	 * the array walk into an unrelated heap allocation.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->argv = (void **) argv;
	snap->envp = (void **) envp;
	snap->argvcount = argvcount;
	snap->envpcount = envpcount;
	rec->post_state = (unsigned long) snap;
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
	struct execve_post_state *snap = (struct execve_post_state *) rec->post_state;

	rec->a2 = 0;
	rec->a3 = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_execve: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner array pointers may no longer reference our heap
	 * allocations.  free_execve_ptrs() walks argv[]/envp[] before
	 * free()ing the outer arrays, and a bad pointer crashes on the
	 * first deref.  Leak rather than walk garbage.
	 */
	if (looks_like_corrupted_ptr(rec, snap->argv) ||
	    looks_like_corrupted_ptr(rec, snap->envp)) {
		outputerr("post_execve: rejected suspicious argv=%p envp=%p "
			  "(post_state-scribbled?)\n", snap->argv, snap->envp);
		deferred_freeptr(&rec->post_state);
		return;
	}
	/*
	 * sanitise_execve() bounds both counts by rand() % 32; anything
	 * over 32 means the snapshot was scribbled.  Walking the array
	 * with a bogus count reads far past the end of the allocation,
	 * so leak instead — the child process is dying anyway.
	 */
	if (snap->argvcount > 32 || snap->envpcount > 32) {
		outputerr("post_execve: rejected suspicious argvcount=%lu envpcount=%lu "
			  "(post_state-scribbled?)\n", snap->argvcount, snap->envpcount);
		deferred_freeptr(&rec->post_state);
		return;
	}
	free_execve_ptrs(snap->argv, snap->envp, snap->argvcount, snap->envpcount);
	deferred_freeptr(&rec->post_state);
}

static void post_execveat(struct syscallrecord *rec)
{
	struct execve_post_state *snap = (struct execve_post_state *) rec->post_state;

	rec->a3 = 0;
	rec->a4 = 0;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_execveat: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	if (looks_like_corrupted_ptr(rec, snap->argv) ||
	    looks_like_corrupted_ptr(rec, snap->envp)) {
		outputerr("post_execveat: rejected suspicious argv=%p envp=%p "
			  "(post_state-scribbled?)\n", snap->argv, snap->envp);
		deferred_freeptr(&rec->post_state);
		return;
	}
	if (snap->argvcount > 32 || snap->envpcount > 32) {
		outputerr("post_execveat: rejected suspicious argvcount=%lu envpcount=%lu "
			  "(post_state-scribbled?)\n", snap->argvcount, snap->envpcount);
		deferred_freeptr(&rec->post_state);
		return;
	}
	free_execve_ptrs(snap->argv, snap->envp, snap->argvcount, snap->envpcount);
	deferred_freeptr(&rec->post_state);
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
