/*
 * SYSCALL_DEFINE6(getxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name,
 *		struct xattr_args __user *, uargs, size_t, usize)
 */
#include "arch.h"
#include "deferred-free.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "xattr.h"
#include "compat.h"
#ifdef USE_XATTR_ARGS
#include <linux/xattr.h>
#endif

/*
 * Snapshot of the value-buffer bound captured at sanitise time and
 * consumed by the post handler.  Lives in rec->post_state so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot smear the size cap used to
 * validate the retval.
 */
#define GETXATTRAT_POST_STATE_MAGIC	0x47585441UL	/* "GXTA" */
struct getxattrat_post_state {
	unsigned long magic;
	unsigned long size;
};

static void sanitise_getxattrat(struct syscallrecord *rec)
{
#ifdef USE_XATTR_ARGS
	struct getxattrat_post_state *snap;
#endif

	rec->post_state = 0;

	if (!sanitise_xattr_name_arg(rec, 4))
		return;

#ifdef USE_XATTR_ARGS
	{
		struct xattr_args *args;
		void *value;

		args = (struct xattr_args *) get_writable_struct(sizeof(*args));
		if (!args)
			return;
		value = get_writable_struct(256);
		if (!value)
			return;
		args->value = (unsigned long) value;
		args->size = 256;
		args->flags = 0;
		rec->a5 = (unsigned long) args;
		avoid_shared_buffer_inout(&rec->a5, sizeof(struct xattr_args));
		rec->a6 = sizeof(*args);

		snap = zmalloc_tracked(sizeof(*snap));
		snap->magic = GETXATTRAT_POST_STATE_MAGIC;
		snap->size = args->size;
		rec->post_state = (unsigned long) snap;
	}
#else
	avoid_shared_buffer_out(&rec->a5, page_size);
#endif
}

/*
 * STRONG-VAL count bound: getxattrat(2) returns the number of bytes
 * written into the user value buffer (the buffer pointed at by
 * xattr_args.value), capped by xattr_args.size.  Failure returns
 * -1UL.  A retval > snap->size on a non-(-1UL) return is structurally
 * impossible from the VFS path -- it points at a sign-extension tear,
 * a sibling-stomp of rec->retval between syscall return and post
 * entry, or -errno leaking through the success slot.
 *
 * The non-at variants getxattr/lgetxattr/fgetxattr install equivalent
 * post handlers instead of advertising RET_ZERO_SUCCESS, which would
 * otherwise route every legitimate positive return through the
 * dispatcher's rzs_blanket_reject increment.
 */
static void post_getxattrat(struct syscallrecord *rec)
{
	struct getxattrat_post_state *snap =
		(struct getxattrat_post_state *) rec->post_state;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_getxattrat: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (snap->magic != GETXATTRAT_POST_STATE_MAGIC) {
		outputerr("post_getxattrat: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	if ((long) rec->retval >= 0 && snap->size != 0 &&
	    rec->retval > snap->size) {
		outputerr("post_getxattrat: rejecting retval %lu > size %lu\n",
			  rec->retval, snap->size);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_getxattrat = {
	.name = "getxattrat",
	.num_args = 6,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [4] = ARG_ADDRESS, [5] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "at_flags", [3] = "name", [4] = "uargs", [5] = "usize" },
	.arg_params[2].list = ARGLIST(xattrat_flags),
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_getxattrat,
	.post = post_getxattrat,
};
