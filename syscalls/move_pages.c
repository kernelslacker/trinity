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
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the three heap allocations sanitise hands to the kernel,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so the post
 * path is immune to a sibling syscall scribbling rec->a3/a4/a5 between
 * the syscall returning and the post handler running.
 */
struct move_pages_post_state {
	unsigned long *pages;
	int *nodes;
	int *status;
};

static void sanitise_move_pages(struct syscallrecord *rec)
{
	struct move_pages_post_state *snap;
	int *nodes, *status;
	unsigned long *page_alloc;
	unsigned int i;
	unsigned int count;

	/* Clear post_state up front so the early-return paths below cannot
	 * leave stale data from a previous syscall in the slot. */
	rec->post_state = 0;

	/* number of pages to move */
	count = rand() % (page_size / sizeof(void *));
	count = max(1U, count);
	rec->a2 = count;

	/* setup array of ptrs to pages to move */
	page_alloc = (unsigned long *) zmalloc(page_size);

	for (i = 0; i < count; i++) {
		struct map *map;

		map = get_map();
		page_alloc[i] = (unsigned long) (map ? map->ptr : NULL);
	}
	rec->a3 = (unsigned long) page_alloc;

	/* nodes = array of ints specifying desired location for each page */
	nodes = calloc(count, sizeof(int));
	if (!nodes) {
		rec->a5 = 0;
		deferred_freeptr(&rec->a3);
		return;
	}
	for (i = 0; i < count; i++)
		nodes[i] = (int) RAND_BOOL();
	rec->a4 = (unsigned long) nodes;

	/* status = array of ints returning status of each page.*/
	status = calloc(count, sizeof(int));
	rec->a5 = (unsigned long) status;
	if (!status) {
		free(nodes);
		rec->a4 = 0;
		deferred_freeptr(&rec->a3);
		return;
	}

	/* Needs CAP_SYS_NICE */
	if (getuid() != 0)
		rec->a6 &= ~MPOL_MF_MOVE_ALL;

	/*
	 * Snapshot all three heap pointers for the post handler.  A sibling
	 * syscall can scribble rec->a3/a4/a5 between the syscall returning
	 * and the post handler running, leaving real-but-wrong heap
	 * pointers that looks_like_corrupted_ptr() cannot distinguish from
	 * the originals; the post handler then hands the wrong allocations
	 * to free, leaking ours and corrupting another sanitise routine's
	 * live buffers.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->pages = page_alloc;
	snap->nodes = nodes;
	snap->status = status;
	rec->post_state = (unsigned long) snap;
}

static void post_move_pages(struct syscallrecord *rec)
{
	struct move_pages_post_state *snap = (struct move_pages_post_state *) rec->post_state;

	rec->a3 = 0;
	rec->a4 = 0;
	rec->a5 = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_move_pages: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner pointers may no longer reference our heap allocations.
	 * Leak rather than hand garbage to free().
	 */
	if (looks_like_corrupted_ptr(snap->pages) ||
	    looks_like_corrupted_ptr(snap->nodes) ||
	    looks_like_corrupted_ptr(snap->status)) {
		outputerr("post_move_pages: rejected suspicious snap pages=%p "
			  "nodes=%p status=%p (post_state-scribbled?)\n",
			  snap->pages, snap->nodes, snap->status);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		deferred_freeptr(&rec->post_state);
		return;
	}

	deferred_free_enqueue(snap->pages, NULL);
	deferred_free_enqueue(snap->nodes, NULL);
	deferred_free_enqueue(snap->status, NULL);
	deferred_freeptr(&rec->post_state);
}

static unsigned long move_pages_flags[] = {
	MPOL_MF_MOVE, MPOL_MF_MOVE_ALL,
};

struct syscallentry syscall_move_pages = {
	.name = "move_pages",
	.num_args = 6,
	.argtype = { [0] = ARG_PID, [1] = ARG_LEN, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS, [5] = ARG_LIST },
	.argname = { [0] = "pid", [1] = "nr_pages", [2] = "pages", [3] = "nodes", [4] = "status", [5] = "flags" },
	.arg_params[5].list = ARGLIST(move_pages_flags),
	.group = GROUP_VM,
	.sanitise = sanitise_move_pages,
	.post = post_move_pages,
};
