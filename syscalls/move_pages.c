/*
 * SYSCALL_DEFINE6(move_pages, pid_t, pid, unsigned long, nr_pages,
	const void __user * __user *, pages,
	const int __user *, nodes,
	int __user *, status, int, flags)
 */

#define MPOL_MF_MOVE    (1<<1)  /* Move pages owned by this process to conform to mapping */
#define MPOL_MF_MOVE_ALL (1<<2) /* Move every page to conform to mapping */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "trinity.h"
#include "sanitise.h"
#include "arch.h"

static void sanitise_move_pages(unsigned long *pid,
	unsigned long *nr_pages, unsigned long *pages,
	unsigned long *nodes,unsigned long *status, unsigned long *flags)
{
	unsigned long *page_alloc;
	unsigned int i;

	// Needs CAP_SYS_NICE to move pages in another process
	if (getuid() != 0) {
		*pid = 0;
		*flags &= ~MPOL_MF_MOVE_ALL;
	}

	page_alloc = malloc(page_size);

	*nr_pages = rand() % (page_size / sizeof(void *));

	for (i = 0; i < *nr_pages; i++) {
		page_alloc[i] = (unsigned long) malloc(page_size);
		page_alloc[i] &= PAGE_MASK;
	}

	*pages = (unsigned long) page_alloc;

	*nodes = (unsigned long) malloc(page_size);
	for (i = 0; i < page_size; i++) {
		*nodes = (int) rand() % 2;
	}

	*status = (unsigned long) malloc(page_size);
}

struct syscall syscall_move_pages = {
	.name = "move_pages",
	.num_args = 6,
	.arg1name = "pid",
	.arg2name = "nr_pages",
	.arg3name = "pages",
	.arg4name = "nodes",
	.arg5name = "status",
	.arg5type = ARG_ADDRESS,
	.arg6name = "flags",
	.arg6type = ARG_LIST,
	.arg6list = {
		.num = 2,
		.values = { MPOL_MF_MOVE, MPOL_MF_MOVE_ALL },
	},
	.group = GROUP_VM,
	.sanitise = sanitise_move_pages,
};
