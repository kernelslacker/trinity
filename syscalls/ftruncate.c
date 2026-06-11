/*
 * SYSCALL_DEFINE2(ftruncate, unsigned int, fd, unsigned long, length)
 */
#include "fd.h"
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

	/* Belt-and-suspenders: keep the stderr capture memfd (and other
	 * protected fds) out of rec->a1 so a fuzz-induced ftruncate can't
	 * extend it to multi-GB and turn the next SIGABRT-handler bug-log
	 * drain into a host-swamping write. */
	reroll_protected_fd_arg(&rec->a1);

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = FTRUNCATE_POST_STATE_MAGIC;
	snap->fd    = rec->a1;
	post_state_install(rec, snap);
}

static void post_ftruncate(struct syscallrecord *rec)
{
	struct ftruncate_post_state *snap;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, FTRUNCATE_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

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
	post_state_release(rec, snap);
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
