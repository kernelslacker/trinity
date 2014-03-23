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
#include <stdio.h>
#include <stdlib.h>
#include "arch.h"	// page_size
#include "random.h"	// generate_random_page
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"	// __unused__

static unsigned long ** gen_ptrs_to_crap(void)
{
	void **ptr;
	unsigned int i;
	unsigned int count = rand() % 32;

	/* Fabricate argv */
	ptr = malloc(count * sizeof(void *));	// FIXME: LEAK
	if (ptr == NULL)
		return NULL;

	for (i = 0; i < count; i++) {
		ptr[i] = malloc(page_size);	// FIXME: LEAK
		if (ptr[i] != NULL)
			generate_random_page((char *) ptr[i]);
	}

	return (unsigned long **) ptr;
}

static void sanitise_execve(__unused__ int childno)
{
	/* we don't want to block if something tries to read from stdin */
	fclose(stdin);

	/* Fabricate argv */
	shm->syscall[childno].a2 = (unsigned long) gen_ptrs_to_crap();

	/* Fabricate envp */
	shm->syscall[childno].a3 = (unsigned long) gen_ptrs_to_crap();
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
	.group = GROUP_VFS,
};
