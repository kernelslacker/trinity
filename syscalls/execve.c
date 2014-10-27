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
#include "trinity.h"	// __unused__
#include "utils.h"

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
		generate_rand_bytes((unsigned char *) ptr[i], rand() % page_size);
	}

	return (unsigned long **) ptr;
}

static void sanitise_execve(struct syscallrecord *rec)
{
	/* we don't want to block if something tries to read from stdin */
	fclose(stdin);

	/* Fabricate argv */
	argvcount = rand() % 32;
	rec->a2 = (unsigned long) gen_ptrs_to_crap(argvcount);

	/* Fabricate envp */
	envpcount = rand() % 32;
	rec->a3 = (unsigned long) gen_ptrs_to_crap(envpcount);
}

/* if execve succeeds, we'll never get back here, so this only
 * has to worry about the case where execve returned a failure.
 */
static void post_execve(struct syscallrecord *rec)
{
	void **ptr;
	unsigned int i;

	ptr = (void **) rec->a2;
	for (i = 0; i < argvcount; i++)
		free(ptr[i]);
	free(ptr);

	ptr = (void **) rec->a3;
	for (i = 0; i < envpcount; i++)
		free(ptr[i]);
	free(ptr);
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
	.errnos = {
		.num = 17,
		.values = {
			E2BIG, EACCES, EFAULT, EINVAL, EIO, EISDIR, ELIBBAD, ELOOP,
			EMFILE, ENOENT, ENOEXEC, ENOMEM, ENOTDIR, EPERM, ETXTBSY,
			/* currently undocumented in man page. */
			ENAMETOOLONG, ENXIO,
		},
	},
};
