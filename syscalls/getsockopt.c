/*
 * SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname, char __user *, optval, int __user *, optlen)
 */
#include <stdlib.h>
#include "arch.h"
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "utils.h"
#include "valresult.h"

/*
 * Snapshot for the post handler.  Both the optval buffer (a4) and the
 * lenp pointer (a5) are zmalloc()'d (via valresult_alloc) and then
 * handed to avoid_shared_buffer(), which relocates them off the libc
 * heap into a parent-private writable region.  deferred_free_enqueue()
 * rejects the relocated address (heap-bounds and alloc-track gates
 * both fail) so freeing rec->a4 / rec->a5 in the post handler leaks
 * the originals.
 *
 * Snapshot the whole valresult_buf BEFORE avoid_shared_buffer() runs:
 * vrb.buf and vrb.len_io are the zmalloc results we hand back to
 * deferred_free_enqueue() through valresult_free().  The cookie
 * hardens the post handler against a sibling scribbling rec->post_state
 * with a heap-shaped pointer to a foreign allocation -- the cookie
 * mismatch rejects the forgery before any inner-field deref.
 */
#define GETSOCKOPT_POST_STATE_MAGIC	0x474554534F50545FUL	/* "GETSOPT_" */
struct getsockopt_post_state {
	unsigned long magic;
	struct valresult_buf vrb;
};

static void sanitise_getsockopt(struct syscallrecord *rec)
{
	struct sockopt so = { 0, 0, 0, 0 };
	struct socketinfo *si;
	struct socket_triplet *triplet = NULL;
	struct getsockopt_post_state *snap;
	struct valresult_buf vrb;
	int fd;

	si = (struct socketinfo *) rec->a1;
	if (si == NULL) {
		rec->a1 = get_random_fd();
		return;
	}

	if (ONE_IN(1000)) {
		fd = get_random_fd();
	} else {
		fd = si->fd;
		triplet = &si->triplet;
	}

	rec->a1 = fd;

	do_setsockopt(&so, triplet);

	rec->a2 = so.level;
	rec->a3 = so.optname;

	/* do_setsockopt allocates optval — we only needed level/optname. */
	free((void *) so.optval);

	/*
	 * Allocate the output buffer + value-result length slot through
	 * the shared shape catalogue.  The natural capacity for getsockopt
	 * is page_size (most options fit comfortably); the helper mutates
	 * that into the picked shape (EXACT / UNDER / +1 / HUGE / ZERO).
	 *
	 * Both slots come from zmalloc_tracked() and are released via
	 * valresult_free() in the post handler.  rec->a4 / rec->a5 take
	 * the original (pre-relocation) pointers; avoid_shared_buffer()
	 * then rewrites them in place, but the snapshot below preserves
	 * the zmalloc results for the free path.
	 */
	vrb = valresult_alloc(page_size, valresult_pick_shape());
	rec->a4 = (unsigned long) vrb.buf;
	rec->a5 = (unsigned long) vrb.len_io;

	/*
	 * Snapshot the vrb BEFORE avoid_shared_buffer() runs.  a4 and
	 * a5 are both about to be relocated off the libc heap; the post
	 * handler must free the zmalloc results, not the relocated
	 * pointers (which the deferred-free heap-bounds gate rejects).
	 * The snap also doubles as a sibling-scribble shield: a foreign
	 * heap-shaped pointer parked in rec->post_state survives
	 * looks_like_corrupted_ptr() but fails the magic check.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = GETSOCKOPT_POST_STATE_MAGIC;
	snap->vrb = vrb;
	rec->post_state = (unsigned long) snap;

	/*
	 * The kernel writes the option value through optval (a4) up to
	 * *optlen bytes and updates *optlen (a5) with the actual count.
	 * a4 is purely output -- use _out so the relocated buffer is left
	 * untouched.  a5 is value-result -- the kernel reads the initial
	 * size before writing back the actual count, so it must be _inout
	 * to preserve the *len_io = cap valresult_alloc() just stored.
	 *
	 * When the shape picked cap == 0 the buf is NULL (rec->a4 == 0)
	 * and avoid_shared_buffer_out() short-circuits on that.  The
	 * lenp slot is always allocated so a5 always has a valid target.
	 */
	avoid_shared_buffer_out(&rec->a4, vrb.cap);
	avoid_shared_buffer_inout(&rec->a5, sizeof(*vrb.len_io));
}

static void post_getsockopt(struct syscallrecord *rec)
{
	struct getsockopt_post_state *snap =
		(struct getsockopt_post_state *) rec->post_state;

	if (snap == NULL) {
		rec->a4 = 0;
		rec->a5 = 0;
		return;
	}

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_getsockopt: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->a4 = 0;
		rec->a5 = 0;
		rec->post_state = 0;
		return;
	}

	if (snap->magic != GETSOCKOPT_POST_STATE_MAGIC) {
		outputerr("post_getsockopt: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a4 = 0;
		rec->a5 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a4 = 0;
	rec->a5 = 0;
	valresult_free(&snap->vrb);
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_getsockopt = {
	.name = "getsockopt",
	.num_args = 5,
	.argtype = { [0] = ARG_SOCKETINFO },
	.argname = { [0] = "fd", [1] = "level", [2] = "optname", [3] = "optval", [4] = "optlen" },
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_getsockopt,
	.post = post_getsockopt,
	.rettype = RET_ZERO_SUCCESS,
};
