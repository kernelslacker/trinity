/*
 * SYSCALL_DEFINE6(move_pages, pid_t, pid, unsigned long, nr_pages,
	const void __user * __user *, pages,
	const int __user *, nodes,
	int __user *, status, int, flags)
 */

#define MPOL_MF_MOVE    (1<<1)  /* Move pages owned by this process to conform to mapping */
#define MPOL_MF_MOVE_ALL (1<<2) /* Move every page to conform to mapping */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"	// page_size

static unsigned int count;

#define WAS_MALLOC 1
#define WAS_MAP 2
static unsigned char *pagetypes;

static void sanitise_move_pages(int childno)
{
	struct map *map;
	int *nodes;
	unsigned long *page_alloc;
	unsigned int i, j;

	pagetypes = zmalloc(page_size);

	/* number of pages to move */
	count = rand() % (page_size / sizeof(void *));
	count = max(1, count);
	shm->a2[childno] = count;

	/* setup array of ptrs to pages to move */
	page_alloc = (unsigned long *) malloc(page_size);
	if (page_alloc == NULL)
		return;
	shm->scratch[childno] = (unsigned long) page_alloc;

	for (i = 0; i < count; i++) {
		if (rand_bool()) {
			/* malloc */
			page_alloc[i] = (unsigned long) malloc(page_size);
			if (!page_alloc[i]) {
				for (j = 0; j < i; j++) {
					if (pagetypes[j] == WAS_MALLOC)
						free((void *)page_alloc[j]);
				}
				free(page_alloc);
				return;
			}
			page_alloc[i] &= PAGE_MASK;
			pagetypes[i] = WAS_MALLOC;
		} else {
			/* mapping. */
			map = get_map();
			page_alloc[i] = (unsigned long) map->ptr;
			pagetypes[i] = WAS_MAP;
		}
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
		if (pagetypes[i] == WAS_MALLOC)
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
