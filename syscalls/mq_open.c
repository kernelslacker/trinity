/*
 * SYSCALL_DEFINE4(mq_open, const char __user *, u_name, int, oflag, mode_t, mode, struct mq_attr __user *, u_attr)
 */
#include <fcntl.h>
#include <mqueue.h>
#include <string.h>
#include <unistd.h>
#include "deferred-free.h"
#include "random.h"
#include "rnd.h"
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
#define MQ_OPEN_POST_STATE_MAGIC	0x4D515F4F50454E5FUL	/* "MQ_OPEN_" */
struct mq_open_post_state {
	unsigned long magic;
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
	name[5] = '0' + (rnd_modulo_u32(10));
	name[6] = '\0';

	attr = (struct mq_attr *) get_writable_struct(sizeof(*attr));
	if (!attr)
		return;
	memset(attr, 0, sizeof(*attr));

	switch (rnd_modulo_u32(3)) {
	case 0:	/* small queue */
		attr->mq_maxmsg = 1;
		attr->mq_msgsize = 1;
		break;
	case 1: /* typical */
		attr->mq_maxmsg = 10;
		attr->mq_msgsize = 8192;
		break;
	default: /* boundary */
		attr->mq_maxmsg = 1 + (rnd_modulo_u32(256));
		attr->mq_msgsize = 1 + (rnd_modulo_u32(65536));
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
	 * string.  post_state is private to the post / cleanup pair.
	 *
	 * Lifetime is owned by the canonical install / claim_owned /
	 * release bracket.  post_state_install() couples the rec->post_state
	 * assign with the ownership-table register so the observable window
	 * between the two is closed; post_mq_open() runs the snap through
	 * post_state_claim_owned() (shape -> ownership -> magic) and
	 * post_state_release() on every exit path it reaches.  The release
	 * gate is idempotent, so cleanup_mq_open() funnels its still-live
	 * rec->post_state through the same release helper as a safety net
	 * for paths that skip .post entirely (retfd_rejected / rzs_rejected
	 * in handle_syscall_ret(), --dry-run synthesised ENOSYS, EXTRA_FORK
	 * SIGKILL before AFTER): the second call short-circuits on the
	 * already-released gate when .post got there first, and unregisters
	 * + frees when .post never ran.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = MQ_OPEN_POST_STATE_MAGIC;
	snap->name  = rec->a1;
	snap->oflag = rec->a2;
	snap->mode  = rec->a3;
	snap->attr  = rec->a4;
	post_state_install(rec, snap);
}

static void post_mq_open(struct syscallrecord *rec)
{
	struct mq_open_post_state *snap;
	unsigned long retval = rec->retval;
	long ret = (long) retval;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, MQ_OPEN_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if (ret < 0) {
		post_state_release(rec, snap);
		return;
	}

	if (retval >= (1UL << 20)) {
		outputerr("post_mq_open: rejecting out-of-bound fd=%ld\n", ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
		post_state_release(rec, snap);
		return;
	}

	/* Don't close fd here: the dispatcher's register_returned_fd()
	 * runs after this handler and claims the fd into the OBJ_FD_MQ
	 * OBJ_LOCAL pool (via the .ret_objtype annotation on the
	 * syscallentry).  mq_destructor handles close() at child
	 * teardown.  mq_unlink below still removes the named entry from
	 * the queue namespace so subsequent iterations re-binding the
	 * same name don't EEXIST -- the kernel keeps the queue alive
	 * for the open fd until its last close.
	 */

	{
		void *name = (void *)(unsigned long) snap->name;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner name
		 * field.  Reject pid-scribbled name before mq_unlink.
		 */
		if (name == NULL) {
			post_state_release(rec, snap);
			return;
		}
		if (looks_like_corrupted_ptr(rec, name)) {
			outputerr("post_mq_open: rejected suspicious u_name=%p (post_state-scribbled?)\n",
				  name);
			post_state_release(rec, snap);
			return;
		}
	}

	/* Also unlink the queue to avoid leaking kernel IPC resources.
	 * The name pointer comes from the snapshot captured at sanitise
	 * time, not from rec->a1, so a sibling that scribbled the syscall
	 * arg slot in the TOCTOU window between guard and mq_unlink
	 * cannot redirect this call at a foreign string.
	 */
	mq_unlink((const char *) snap->name);

	post_state_release(rec, snap);
}

static void cleanup_mq_open(struct syscallrecord *rec)
{
	/*
	 * Do NOT zero rec->a1 here: a1 carries the name buffer pointer
	 * returned by get_writable_struct(), which lives in a separate
	 * pool with its own lifecycle (not the snap allocation).  Zeroing
	 * it would drop the syscall-arg ABI's view of the input without
	 * any matching free.
	 *
	 * Funnel rec->post_state through the same post_state_release()
	 * the .post handler uses.  Idempotent: on the success / inner-ptr
	 * reject paths .post has already released and cleared
	 * rec->post_state to 0, so this call short-circuits on the NULL
	 * snap.  On the claim-owned reject paths .post cleared
	 * rec->post_state too (the helper does so before returning NULL),
	 * same short-circuit.  On skip-.post paths (retfd_rejected /
	 * rzs_rejected in handle_syscall_ret(), validator-rejected
	 * early-EINVAL, --dry-run synthesised ENOSYS, EXTRA_FORK SIGKILL
	 * before AFTER) rec->post_state still carries the live snap, so
	 * the helper unregisters the ownership-table slot and routes the
	 * chunk through deferred_freeptr().  The already-released gate in
	 * post_state_release() makes a second-release attempt on the same
	 * snap a counter bump rather than a libc free abort, so the
	 * .post/.cleanup pair is balanced and called exactly once across
	 * every dispatch outcome.
	 */
	post_state_release(rec, (void *) rec->post_state);
}

struct syscallentry syscall_mq_open = {
	.name = "mq_open",
	.group = GROUP_IPC,
	.num_args = 4,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LIST, [2] = ARG_MODE_T, [3] = ARG_ADDRESS },
	.argname = { [0] = "u_name", [1] = "oflag", [2] = "mode", [3] = "u_attr" },
	.arg_params[1].list = ARGLIST(mq_open_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_MQ,
	.sanitise = sanitise_mq_open,
	.post = post_mq_open,
	.cleanup = cleanup_mq_open,
};
