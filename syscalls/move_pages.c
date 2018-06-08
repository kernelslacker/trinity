/*
 * SYSCALL_DEFINE6(move_pages, pid_t, pid, unsigned long, nr_pages,
	const void __user * __user *, pages,
	const int __user *, nodes,
	int __user *, status, int, flags)
 */

#define MPOL_MF_MOVE    (1<<1)  /* Move pages owned by this process to conform to mapping */
#define MPOL_MF_MOVE_ALL (1<<2) /* Move every page to conform to mapping */

#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_move_pages(struct syscallrecord *rec)
{
	int *nodes;
	unsigned long *page_alloc;
	unsigned int i;
	unsigned int count;

	/* number of pages to move */
	count = rnd() % (page_size / sizeof(void *));
	count = max(1U, count);
	rec->a2 = count;

	/* setup array of ptrs to pages to move */
	page_alloc = (unsigned long *) zmalloc(page_size);

	for (i = 0; i < count; i++) {
		struct map *map;

		map = get_map();
		page_alloc[i] = (unsigned long) map->ptr;
	}
	rec->a3 = (unsigned long) page_alloc;

	/* nodes = array of ints specifying desired location for each page */
	nodes = calloc(count, sizeof(int));
	for (i = 0; i < count; i++)
		nodes[i] = (int) RAND_BOOL();
	rec->a4 = (unsigned long) nodes;

	/* status = array of ints returning status of each page.*/
	rec->a5 = (unsigned long) calloc(count, sizeof(int));

	/* Needs CAP_SYS_NICE */
	if (getuid() != 0)
		rec->a6 &= ~MPOL_MF_MOVE_ALL;
}

static void post_move_pages(struct syscallrecord *rec)
{
	freeptr(&rec->a3);
	freeptr(&rec->a4);
	freeptr(&rec->a5);
}

static unsigned long move_pages_flags[] = {
	MPOL_MF_MOVE, MPOL_MF_MOVE_ALL,
};

struct syscallentry syscall_move_pages = {
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
	.arg6list = ARGLIST(move_pages_flags),
	.group = GROUP_VM,
	.sanitise = sanitise_move_pages,
	.post = post_move_pages,
};
