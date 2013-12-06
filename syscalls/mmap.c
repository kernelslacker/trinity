/*
 * SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, unsigned long, off)
 */
#include <stdlib.h>
#include <sys/mman.h>
#include "trinity.h"	// page_size
#include "sanitise.h"
#include "shm.h"
#include "arch.h"
#include "compat.h"
#include "random.h"

#ifdef __x86_64__
#define NUM_FLAGS 13
#else
#define NUM_FLAGS 12
#endif

// need this to actually get MAP_UNINITIALIZED defined
#define CONFIG_MMAP_ALLOW_UNINITIALIZED

static void do_anon(int childno)
{
	/* no fd if anonymous mapping. */
	shm->a5[childno] = -1;
	shm->a6[childno] = 0;
}

void sanitise_mmap(int childno)
{
	unsigned int i;
	unsigned int flagvals[NUM_FLAGS] = { MAP_FIXED, MAP_ANONYMOUS,
			MAP_GROWSDOWN, MAP_DENYWRITE, MAP_EXECUTABLE, MAP_LOCKED,
			MAP_NORESERVE, MAP_POPULATE, MAP_NONBLOCK, MAP_STACK,
			MAP_HUGETLB, MAP_UNINITIALIZED,
#ifdef __x86_64__
			MAP_32BIT,
#endif
	};
	unsigned int numflags = rand() % NUM_FLAGS;

	/* Don't actually set a hint right now. */
	shm->a1[childno] = 0;

	shm->a2[childno] = page_size;
	if (shm->a2[childno] == 0)
		shm->a2[childno] = page_size;


	// set additional flags
	for (i = 0; i < numflags; i++)
		shm->a4[childno] |= flagvals[rand() % NUM_FLAGS];

	if (shm->a4[childno] & MAP_ANONYMOUS) {
		do_anon(childno);
	} else {
		/* page align non-anonymous mappings. */
		shm->a6[childno] &= PAGE_MASK;
	}
}

static void post_mmap(int childno)
{
	char *p;

	p = (void *) shm->retval[childno];
	if (p == MAP_FAILED)
		return;

	//FIXME: Need to check here for PROT_WRITE when we add per-child mapping list.

	/* Sometimes dirty the mapping. */
	if (rand_bool())
		p[rand() % page_size] = 1;

	//TODO: Add this to a list for use by subsequent syscalls.
}

struct syscall syscall_mmap = {
	.name = "mmap",
	.num_args = 6,
	.sanitise = sanitise_mmap,
	.arg1name = "addr",
	.arg1type = ARG_MMAP,
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.arg3name = "prot",
	.arg3type = ARG_LIST,
	.arg3list = {
		.num = 4,
		.values = { PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM },
	},
	.arg4name = "flags",
	.arg4type = ARG_OP,
	.arg4list = {
		.num = 2,
		.values = { MAP_SHARED, MAP_PRIVATE },
	},
	.arg5name = "fd",
	.arg5type = ARG_FD,
	.arg6name = "off",
	.arg6type = ARG_LEN,
	.group = GROUP_VM,
	.flags = NEED_ALARM,
	.post = post_mmap,
};
