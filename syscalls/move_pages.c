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
#include "utils.h"	// page_size
#include "sanitise.h"
#include "arch.h"
#include "shm.h"

static unsigned int count;

static void sanitise_move_pages(int childno)
{
	int *nodes;
	unsigned long *page_alloc;
	unsigned int i, j;

	/* number of pages to move */
	count = rand() % (page_size / sizeof(void *));
	count = max(1, count);
	shm->a2[childno] = count;

	/* setup array of ptrs to pages to move */
	page_alloc = (unsigned long *) malloc(page_size);
	shm->scratch[childno] = (unsigned long) page_alloc;
	if (page_alloc == NULL)
		return;

	for (i = 0; i < count; i++) {
		page_alloc[i] = (unsigned long) malloc(page_size);
		if (!page_alloc[i]) {
			for (j = 0; j < i; j++)
				free((void *)page_alloc[j]);
			free(page_alloc);
			return;
		}
		page_alloc[i] &= PAGE_MASK;
	}
	shm->a3[childno] = (unsigned long) page_alloc;

	/* nodes = array of ints specifying desired location for each page */
	nodes = malloc(count * sizeof(int));
	for (i = 0; i < count; i++)
		nodes[i] = (int) rand() % 2;
	shm->a4[childno] = (unsigned long) nodes;

	/* status = array of ints returning status of each page.*/
	shm->a5[childno] = (unsigned long) zmalloc(count * sizeof(int));

	/* Needs CAP_SYS_NICE */
	if (getuid() != 0)
		shm->a6[childno] &= ~MPOL_MF_MOVE_ALL;
}

static void post_move_pages(int childno)
{
	unsigned long *page;
	void *ptr;
	unsigned int i;

	page = (void *) shm->scratch[childno];
	if (page == NULL)
		return;

	for (i = 0; i < count; i++) {
		ptr = (void *) page[i];
		free(ptr);
	}

	free(page);
}

struct syscall syscall_move_pages = {
	.name = "move_pages",
	.num_args = 6,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "nr_pages",
	.arg3name = "pages",
	.arg4name = "nodes",
	.arg5name = "status",
	.arg6name = "flags",
	.arg6type = ARG_LIST,
	.arg6list = {
		.num = 2,
		.values = { MPOL_MF_MOVE, MPOL_MF_MOVE_ALL },
	},
	.group = GROUP_VM,
	.sanitise = sanitise_move_pages,
	.post = post_move_pages,
};
