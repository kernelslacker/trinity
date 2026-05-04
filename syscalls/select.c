/*
 * SYSCALL_DEFINE5(select, int, n, fd_set __user *, inp, fd_set __user *, outp,
	fd_set __user *, exp, struct timeval __user *, tvp)
 */
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the four heap allocations sanitise hands to the kernel,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so the post
 * path is immune to a sibling syscall scribbling rec->a2/a3/a4/a5
 * between the syscall returning and the post handler running.
 */
struct select_post_state {
	fd_set *rfds;
	fd_set *wfds;
	fd_set *exfds;
	struct timeval *tv;
};

static void sanitise_select(struct syscallrecord *rec)
{
	struct select_post_state *snap;
	unsigned int nfds, i, nset;

	struct timeval *tv;
	fd_set *rfds, *wfds, *exfds;

	nfds = (rand32() % 1023) + 1;
	rec->a1 = nfds;

	rfds = zmalloc(sizeof(fd_set));
	wfds = zmalloc(sizeof(fd_set));
	exfds = zmalloc(sizeof(fd_set));

	FD_ZERO(rfds);
	FD_ZERO(wfds);
	FD_ZERO(exfds);

	nset = rand32() % 10;
	/* set some random fd's. */
	for (i = 0; i < nset; i++) {
		FD_SET(rand32() % nfds, rfds);
		FD_SET(rand32() % nfds, wfds);
		FD_SET(rand32() % nfds, exfds);
	}

	rec->a2 = (unsigned long) rfds;
	rec->a3 = (unsigned long) wfds;
	rec->a4 = (unsigned long) exfds;

	/* Set a really short timeout */
	tv = zmalloc(sizeof(struct timeval));
	tv->tv_sec = 0;
	tv->tv_usec = 10;
	rec->a5 = (unsigned long) tv;

	/*
	 * Snapshot all four heap pointers for the post handler.  A sibling
	 * syscall can scribble rec->a2/a3/a4/a5 between the syscall
	 * returning and the post handler running, leaving real-but-wrong
	 * heap pointers that looks_like_corrupted_ptr() cannot distinguish
	 * from the originals; the post handler then hands the wrong
	 * allocations to free, leaking ours and corrupting another sanitise
	 * routine's live buffers.  rec->post_state is private to the post
	 * handler, so the scribblers have nothing to scribble there.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->rfds = rfds;
	snap->wfds = wfds;
	snap->exfds = exfds;
	snap->tv = tv;
	rec->post_state = (unsigned long) snap;
}

static void post_select(struct syscallrecord *rec)
{
	struct select_post_state *snap = (struct select_post_state *) rec->post_state;

	rec->a2 = 0;
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
		outputerr("post_select: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner pointers may no longer reference our heap allocations.
	 * Leak rather than hand garbage to free().
	 */
	if (looks_like_corrupted_ptr(rec, snap->rfds) ||
	    looks_like_corrupted_ptr(rec, snap->wfds) ||
	    looks_like_corrupted_ptr(rec, snap->exfds) ||
	    looks_like_corrupted_ptr(rec, snap->tv)) {
		outputerr("post_select: rejected suspicious snap rfds=%p wfds=%p "
			  "exfds=%p tv=%p (post_state-scribbled?)\n",
			  snap->rfds, snap->wfds, snap->exfds, snap->tv);
		deferred_freeptr(&rec->post_state);
		return;
	}

	deferred_free_enqueue(snap->rfds, NULL);
	deferred_free_enqueue(snap->wfds, NULL);
	deferred_free_enqueue(snap->exfds, NULL);
	deferred_free_enqueue(snap->tv, NULL);
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_select = {
	.name = "select",
	.num_args = 5,
	.argtype = { [0] = ARG_LEN, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS },
	.argname = { [0] = "n", [1] = "inp", [2] = "outp", [3] = "exp", [4] = "tvp" },
	.sanitise = sanitise_select,
	.post = post_select,
	.group = GROUP_VFS,
	.flags = NEED_ALARM,
};
