/*
 * SYSCALL_DEFINE2(ftruncate, unsigned int, fd, unsigned long, length)
 */
#include "deferred-free.h"
#include "maps.h"
#include "sanitise.h"
#include "utils.h"

/*
 * Snapshot of the ftruncate inputs read by the post handler, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->a1 between the syscall returning and the
 * post handler running cannot retarget invalidate_obj_mmap_by_fd() at
 * a foreign fd whose OBJ_MMAP_FILE/TESTFILE entries the ftruncate call
 * never actually affected.
 */
#define FTRUNCATE_POST_STATE_MAGIC	0x46545255UL	/* "FTRU" */
struct ftruncate_post_state {
	unsigned long magic;
	unsigned long fd;
};

static void sanitise_ftruncate(struct syscallrecord *rec)
{
	struct ftruncate_post_state *snap;

	rec->post_state = 0;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = FTRUNCATE_POST_STATE_MAGIC;
	snap->fd    = rec->a1;
	rec->post_state = (unsigned long) snap;
}

static void post_ftruncate(struct syscallrecord *rec)
{
	struct ftruncate_post_state *snap =
		(struct ftruncate_post_state *) rec->post_state;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 * looks_like_corrupted_ptr bumps the corrupt-ptr counter
	 * internally on a positive result; no outputerr here because
	 * child-context output() silently dup2'd /dev/null.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		rec->post_state = 0;
		return;
	}

	if (snap->magic != FTRUNCATE_POST_STATE_MAGIC) {
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	if (rec->retval != 0)
		goto out_free;

	/*
	 * Truncate-down past a mapped extent destroys the backing pages of
	 * the tail and a subsequent access through any OBJ_MMAP_FILE /
	 * TESTFILE entry against this fd SIGBUSes on the first past-EOF
	 * page.  We do not snapshot the pre-call size to gate on
	 * shrink-vs-grow -- a grow is harmless to invalidate (the next
	 * get_map() pick re-populates the pool), the cost is a few extra
	 * mmap-pool refills, and avoiding the gate keeps the post handler
	 * out of an fstat() syscall on the hot path.
	 */
	invalidate_obj_mmap_by_fd((int) snap->fd);

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_ftruncate = {
	.name = "ftruncate",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "length" },
	.sanitise = sanitise_ftruncate,
	.post = post_ftruncate,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE(ftruncate64)(unsigned int fd, loff_t length)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */

struct syscallentry syscall_ftruncate64 = {
	.name = "ftruncate64",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "length" },
	.sanitise = sanitise_ftruncate,
	.post = post_ftruncate,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
