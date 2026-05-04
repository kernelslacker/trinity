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

static void sanitise_getsockopt(struct syscallrecord *rec)
{
	struct sockopt so = { 0, 0, 0, 0 };
	struct socketinfo *si;
	struct socket_triplet *triplet = NULL;
	socklen_t *lenp;
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

	/* Allocate an output buffer for the kernel to write into. */
	rec->a4 = (unsigned long) zmalloc(page_size);

	/* Provide a valid socklen_t pointer initialized to the buffer size. */
	lenp = zmalloc(sizeof(*lenp));
	*lenp = page_size;
	rec->a5 = (unsigned long) lenp;

	/* Snapshot the optval pointer for the post handler -- a4 may be
	 * scribbled by a sibling syscall before post_getsockopt() runs,
	 * leaving a real-but-wrong heap pointer that the corruption guard
	 * cannot distinguish from the original page-sized output buffer.
	 * Without the snapshot the post handler frees the wrong allocation,
	 * leaking ours and corrupting another sanitise routine's live
	 * buffer.  The lenp slot in a5 is a 4-byte allocation that is not
	 * walked, only freed; it is left under the existing path. */
	rec->post_state = rec->a4;
}

static void post_getsockopt(struct syscallrecord *rec)
{
	void *optval = (void *) rec->post_state;

	if (optval != NULL) {
		/*
		 * post_state is private to the post handler, but the whole
		 * syscallrecord can still be wholesale-stomped, so guard the
		 * free path against handing a non-heap value to free().
		 */
		if (looks_like_corrupted_ptr(optval)) {
			outputerr("post_getsockopt: rejected suspicious optval=%p "
				  "(pid-scribbled?)\n", optval);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
			rec->a4 = 0;
			rec->post_state = 0;
		} else {
			rec->a4 = 0;
			deferred_freeptr(&rec->post_state);
		}
	}

	deferred_freeptr(&rec->a5);
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
};
