/*
 * SYSCALL_DEFINE6(getxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name,
 *		struct xattr_args __user *, uargs, size_t, usize)
 */
#include <fcntl.h>
#include <stdbool.h>
#include "arch.h"
#include "csfu.h"
#include "deferred-free.h"
#include "random.h"
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

#ifdef USE_XATTR_ARGS
	{
		struct csfu_buf buf = build_csfu_struct(&desc_getxattrat);
		struct xattr_args *args = buf.ptr;
		bool reaches_vfs;

		if (!args)
			return;

		/*
		 * Hand the csfu buffer to the per-record owned-pointer
		 * carrier so the post-dispatch cleanup drain frees it
		 * deterministically after .post runs.
		 */
		rec_own(rec, args);

		/*
		 * Validator-reject bias: OVERSIZE_NONZERO and TAIL_MISMATCH
		 * are guaranteed -E2BIG out of copy_struct_from_user before
		 * any body field is read.  Half the time pin them back to
		 * EXACT (zero-tail by construction once usize collapses to
		 * ksize) so the call actually reaches path_getxattrat ->
		 * vfs_getxattr.  The remaining half keeps the validator
		 * reject path exercised.
		 */
		if ((buf.bucket == CSFU_BUCKET_OVERSIZE_NONZERO ||
		     buf.bucket == CSFU_BUCKET_TAIL_MISMATCH) && ONE_IN(2)) {
			buf.usize = sizeof(*args);
			buf.bucket = CSFU_BUCKET_EXACT;
		}

		/*
		 * EXACT, UNDERSIZE (= ksize here since the single-version
		 * ABI curates known_sizes to {ksize}), and OVERSIZE_ZERO
		 * all pass copy_struct_from_user and reach the xattr-get
		 * path.  Populate args->value / size / flags + install the
		 * post-handler snap for every bucket that reaches VFS, not
		 * just EXACT, so the bulk of draws exercise the real read
		 * path with a populated value buffer rather than the
		 * size=0 / value=NULL probe shape zmalloc left behind.
		 * OVERSIZE_NONZERO and TAIL_MISMATCH still bounce at the
		 * tail-zero check; leaving them with zeroed args is fine.
		 */
		reaches_vfs = (buf.bucket == CSFU_BUCKET_EXACT ||
			       buf.bucket == CSFU_BUCKET_UNDERSIZE ||
			       buf.bucket == CSFU_BUCKET_OVERSIZE_ZERO);

		if (reaches_vfs) {
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

	/*
	 * at_flags (a3): handle_arg_list's 1/8 shift_flag_bit and 1/16
	 * cmp-hint paths regularly OR in bits outside the kernel-accepted
	 * (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) mask, and path_getxattrat
	 * rejects those with -EINVAL before any xattr-get work runs.
	 * Drop the stray bits on 7/8 of draws so the rejected fraction
	 * stays meaningful for reject-path coverage but does not dominate
	 * the call mix.
	 */
	if (!ONE_IN(8))
		rec->a3 &= (unsigned long)(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH);

	/*
	 * dfd (a1): ARG_FD draws from the full fd pool (regular files,
	 * pipes, sockets, ...).  When pathname is relative the kernel
	 * does a dir-relative lookup against dfd and a non-directory fd
	 * is rejected with -ENOTDIR before VFS-level xattr work.  Pin
	 * to AT_FDCWD on 1/3 of draws so the relative-path fraction
	 * lands on a usable base while leaving the random-fd path well
	 * exercised for the dfd-only (AT_EMPTY_PATH + NULL pathname)
	 * shape.
	 */
	if (ONE_IN(3))
		rec->a1 = (unsigned long)(long) AT_FDCWD;
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
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_XATTR_NAME, [4] = ARG_ADDRESS, [5] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "at_flags", [3] = "name", [4] = "uargs", [5] = "usize" },
	.arg_params[2].list = ARGLIST(xattrat_flags),
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_getxattrat,
	.post = post_getxattrat,
};
