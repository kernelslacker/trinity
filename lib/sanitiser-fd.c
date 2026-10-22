/*
 * The descriptor a sanitiser opened for its call and must close (see
 * include/sanitiser-fd.h).  It is recorded in a post_state snapshot under
 * the ownership table, so a rec->post_state a sibling stomped fails the
 * claim in cleanup and an fd that is not ours stays open.  .cleanup runs
 * once per dispatch on every path; .post is skipped when the dispatcher
 * rejects the return value or the call never reached AFTER.
 */
#include <unistd.h>

#include "sanitiser-fd.h"
#include "syscall.h"
#include "utils.h"

#define SANITISER_FD_POST_STATE_MAGIC	0x53414E49545F4644UL	/* "SANIT_FD" */

struct sanitiser_fd_post_state {
	unsigned long magic;
	int fd;
};

void sanitiser_own_fd(struct syscallrecord *rec, int fd)
{
	struct sanitiser_fd_post_state *snap;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = SANITISER_FD_POST_STATE_MAGIC;
	snap->fd = fd;
	post_state_install(rec, snap);
}

void cleanup_sanitiser_fd(struct syscallrecord *rec)
{
	struct sanitiser_fd_post_state *snap;

	/*
	 * A call that opened nothing has no snapshot, and the claim returns
	 * NULL without complaint.
	 */
	snap = post_state_claim_owned(rec, SANITISER_FD_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	close(snap->fd);
	post_state_release(rec, snap);
}
