/*
 * SYSCALL_DEFINE6(getxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name,
 *		struct xattr_args __user *, uargs, size_t, usize)
 */
#include "arch.h"
#include "csfu.h"
#include "deferred-free.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "xattr.h"
#include "compat.h"
#ifdef USE_XATTR_ARGS
#include <linux/xattr.h>

/*
 * Single-version ABI today: struct xattr_args has only one
 * published layout, so there is no pre-ksize ABI floor to seed the
 * UNDERSIZE bucket from.  The current ksize is kept in
 * known_sizes[] so the table stays self-documenting and remains
 * correct if the kernel ever grows a VER1.
 */
static const size_t getxattrat_known_sizes[] = {
	sizeof(struct xattr_args),
};

static const struct csfu_desc desc_getxattrat = {
	.name = "xattr_args",
	.ksize = sizeof(struct xattr_args),
	.known_sizes = getxattrat_known_sizes,
	.n_known_sizes = ARRAY_SIZE(getxattrat_known_sizes),
};
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
		struct csfu_buf buf = build_csfu_struct(&desc_getxattrat);
		struct xattr_args *args = buf.ptr;

		if (!args)
			return;

		/*
		 * Hand the csfu buffer to the deferred-free queue up front
		 * so the value-buffer allocation failure path below cannot
		 * leak it.
		 */
		deferred_free_enqueue_or_leak(args);

		/*
		 * Non-EXACT buckets get rejected on size by the validator
		 * before the kernel reads any body field, so populating
		 * args->value / size / flags (and allocating the value
		 * sub-buffer they reference) is wasted work.  The
		 * zmalloc_tracked() buffer is already zeroed where the
		 * kernel cares to look.  The post-handler snap is only
		 * meaningful when the kernel actually wrote into the
		 * value buffer, which only happens on EXACT.
		 */
		if (buf.bucket == CSFU_BUCKET_EXACT) {
			void *value = get_writable_struct(256);
			if (!value)
				return;
			args->value = (unsigned long) value;
			args->size = 256;
			args->flags = 0;

			snap = zmalloc_tracked(sizeof(*snap));
			snap->magic = GETXATTRAT_POST_STATE_MAGIC;
			snap->size = args->size;
			post_state_install(rec, snap);
		}

		rec->a5 = (unsigned long) args;
		avoid_shared_buffer_inout(&rec->a5, buf.usize);
		rec->a6 = buf.usize;
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
	struct getxattrat_post_state *snap;
	unsigned long retval = rec->retval;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, GETXATTRAT_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long) retval >= 0 && snap->size != 0 &&
	    retval > snap->size) {
		outputerr("post_getxattrat: rejecting retval %lu > size %lu\n",
			  retval, snap->size);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	post_state_release(rec, snap);
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
