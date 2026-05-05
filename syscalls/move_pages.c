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
	unsigned long count;
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
	snap->count = count;
	rec->post_state = (unsigned long) snap;
}

/*
 * Diagnostic helper for the rejection sample lines below.  Mirrors the
 * banding used by corrupt_ptr_label() in utils.c so the per-handler
 * sample lines and the global corrupt-ptr reject sample line speak the
 * same vocabulary.  Inline-local rather than a shared helper because
 * this whole sample block is investigation scaffolding and is meant to
 * be removable in one commit once the scribble vector is characterised.
 */
static const char *snap_field_label(unsigned long v)
{
	if (v == 0)
		return "NULL";
	if (v < 0x10000)
		return "NULL-ish";
	if (v < 4194304)
		return "pid-shaped";
	if (v >= 0x800000000000UL)
		return "kernel-VA";
	if ((v & 0x7) != 0)
		return "misaligned";
	return "heap-shaped";
}

/*
 * Sample-rate cap for the per-rejection diagnostic lines.  At the
 * observed ~7-8/sec rate from per-handler attribution, 1-in-100 emits
 * roughly 4-5 lines per minute -- enough to characterise the value
 * distribution without flooding logs faster than the operator can
 * read them.  Process-local counter is fine: the goal is sample
 * cadence, not exact 1-in-N globally.
 */
#define MOVE_PAGES_DIAG_INTERVAL	100

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
	if (looks_like_corrupted_ptr(rec, snap)) {
		static unsigned long outer_seq;
		unsigned long n = ++outer_seq;
		if ((n % MOVE_PAGES_DIAG_INTERVAL) == 1) {
			outputerr("post_move_pages-diag: outer-guard reject "
				  "snap=%p label=%s [%lu cumulative]\n",
				  snap,
				  snap_field_label((unsigned long) snap), n);
		}
		rec->post_state = 0;
		return;
	}

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner pointers may no longer reference our heap allocations.
	 * Leak rather than hand garbage to free().
	 */
	if (looks_like_corrupted_ptr(rec, snap->pages) ||
	    looks_like_corrupted_ptr(rec, snap->nodes) ||
	    looks_like_corrupted_ptr(rec, snap->status)) {
		static unsigned long inner_seq;
		unsigned long n = ++inner_seq;
		if ((n % MOVE_PAGES_DIAG_INTERVAL) == 1) {
			outputerr("post_move_pages-diag: inner-guard reject "
				  "snap=%p (heap-shape ok) "
				  "pages=%p[%s] nodes=%p[%s] status=%p[%s] "
				  "count=%lu retval=0x%lx [%lu cumulative]\n",
				  snap,
				  snap->pages,
				  snap_field_label((unsigned long) snap->pages),
				  snap->nodes,
				  snap_field_label((unsigned long) snap->nodes),
				  snap->status,
				  snap_field_label((unsigned long) snap->status),
				  snap->count,
				  (unsigned long) rec->retval, n);
		}
		deferred_freeptr(&rec->post_state);
		return;
	}

	/*
	 * Kernel ABI: sys_move_pages returns the count of pages that
	 * could not be moved, capped at the snapshotted nr_pages arg.
	 * Failure returns -1UL.  Anything > snap->count on a non-(-1UL)
	 * return is a structural ABI regression: a sign-extension tear
	 * in the syscall return path, a kernel-side miscount of unmoved
	 * pages that exceeds the user-supplied bound, or a torn read of
	 * the migration counter.  Inner pointers passed the corruption
	 * guards above, so fall through and still release the
	 * page/node/status arrays via the unified release path below.
	 */
	if ((long) rec->retval != -1L &&
	    (unsigned long) rec->retval > snap->count) {
		outputerr("post_move_pages: retval %lu exceeds requested nr_pages %lu\n",
			  (unsigned long) rec->retval, snap->count);
		post_handler_corrupt_ptr_bump(rec, NULL);
		/* fall through to release allocations */
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
