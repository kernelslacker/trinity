/*
 * SYSCALL_DEFINE4(mq_open, const char __user *, u_name, int, oflag, mode_t, mode, struct mq_attr __user *, u_attr)
 */
#include <fcntl.h>
#include <mqueue.h>
#include <string.h>
#include <unistd.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long mq_open_flags[] = {
	O_RDONLY, O_WRONLY, O_RDWR,
	O_CREAT, O_EXCL, O_NONBLOCK,
};

/*
 * Snapshot of the four mq_open input args read by the post handler,
 * captured at sanitise time and consumed by the post handler.  Lives
 * in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot redirect mq_unlink at a
 * forged name pointer.
 *
 * post_mq_open currently only consumes name, but oflag/mode/attr are
 * snapshotted for symmetry with the rest of the snapshot family and
 * to defend any future post-time use against the same scribble class.
 * The TOCTOU window the snapshot closes is between the existing
 * looks_like_corrupted_ptr guard and the mq_unlink call: with the
 * pre-snapshot code, a sibling stomp landing in that window could
 * push a real-but-wrong heap address into rec->a1 that the guard
 * cannot tell apart from the original name pointer, and mq_unlink
 * would then operate on a foreign string.
 */
struct mq_open_post_state {
	unsigned long name;
	unsigned long oflag;
	unsigned long mode;
	unsigned long attr;
};

static void sanitise_mq_open(struct syscallrecord *rec)
{
	struct mq_open_post_state *snap;
	struct mq_attr *attr;
	char *name;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	/* Generate a valid mq name: must start with '/' */
	name = (char *) get_writable_struct(32);
	if (!name)
		return;
	name[0] = '/';
	name[1] = 't';
	name[2] = 'r';
	name[3] = 'i';
	name[4] = 'n';
	name[5] = '0' + (rand() % 10);
	name[6] = '\0';

	attr = (struct mq_attr *) get_writable_struct(sizeof(*attr));
	if (!attr)
		return;
	memset(attr, 0, sizeof(*attr));

	switch (rand() % 3) {
	case 0:	/* small queue */
		attr->mq_maxmsg = 1;
		attr->mq_msgsize = 1;
		break;
	case 1: /* typical */
		attr->mq_maxmsg = 10;
		attr->mq_msgsize = 8192;
		break;
	default: /* boundary */
		attr->mq_maxmsg = 1 + (rand() % 256);
		attr->mq_msgsize = 1 + (rand() % 65536);
		break;
	}

	if (RAND_BOOL())
		attr->mq_flags = O_NONBLOCK;

	rec->a1 = (unsigned long) name;
	rec->a4 = (unsigned long) attr;

	/*
	 * Snapshot the four input args for the post handler.  Without this
	 * the post handler reads rec->a1 at post-time, when a sibling
	 * syscall may have scribbled the slot.  rec->a1 is corruption-
	 * guarded against pid scribbles, but looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original
	 * name pointer in the writable-struct pool, so a foreign-heap
	 * stomp slips the guard and mq_unlink runs against a foreign
	 * string.  post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->name  = rec->a1;
	snap->oflag = rec->a2;
	snap->mode  = rec->a3;
	snap->attr  = rec->a4;
	rec->post_state = (unsigned long) snap;
}

static void post_mq_open(struct syscallrecord *rec)
{
	struct mq_open_post_state *snap =
		(struct mq_open_post_state *) rec->post_state;
	int fd = rec->retval;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_mq_open: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if ((long)rec->retval < 0)
		goto out_free;

	if ((unsigned long)rec->retval >= (1UL << 20)) {
		outputerr("post_mq_open: rejecting out-of-bound fd=%ld\n", (long)rec->retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

	close(fd);

	{
		void *name = (void *)(unsigned long) snap->name;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner name
		 * field.  Reject pid-scribbled name before mq_unlink.
		 */
		if (name == NULL)
			goto out_free;
		if (looks_like_corrupted_ptr(rec, name)) {
			outputerr("post_mq_open: rejected suspicious u_name=%p (post_state-scribbled?)\n",
				  name);
			goto out_free;
		}
	}

	/* Also unlink the queue to avoid leaking kernel IPC resources.
	 * The name pointer comes from the snapshot captured at sanitise
	 * time, not from rec->a1, so a sibling that scribbled the syscall
	 * arg slot in the TOCTOU window between guard and mq_unlink
	 * cannot redirect this call at a foreign string. */
	mq_unlink((const char *) snap->name);

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_mq_open = {
	.name = "mq_open",
	.group = GROUP_IPC,
	.num_args = 4,
	.argtype = { [1] = ARG_LIST, [2] = ARG_MODE_T },
	.argname = { [0] = "u_name", [1] = "oflag", [2] = "mode", [3] = "u_attr" },
	.arg_params[1].list = ARGLIST(mq_open_flags),
	.rettype = RET_FD,
	.sanitise = sanitise_mq_open,
	.post = post_mq_open,
};
