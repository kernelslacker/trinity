/*
 *  SYSCALL_DEFINE5(name_to_handle_at, int, dfd, const char __user *, name,
 *	struct file_handle __user *, handle, int __user *, mnt_id,
 *	int, flag)
 */
#include <fcntl.h>
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

#ifndef AT_HANDLE_MNT_ID_UNIQUE
#define AT_HANDLE_MNT_ID_UNIQUE 0x001
#endif
#ifndef AT_HANDLE_CONNECTABLE
#define AT_HANDLE_CONNECTABLE   0x002
#endif
#ifndef AT_HANDLE_FID
#define AT_HANDLE_FID           0x200
#endif

static unsigned long name_to_handle_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_HANDLE_FID, AT_SYMLINK_FOLLOW,
	AT_NO_AUTOMOUNT, AT_EMPTY_PATH,
	AT_HANDLE_MNT_ID_UNIQUE, AT_HANDLE_CONNECTABLE,
};

/*
 * Snapshot of the one out-buffer arg the post oracle needs to reason
 * about, captured at sanitise time and consumed by the post handler.
 * Lives in rec->post_state, a slot the syscall ABI does not expose, so
 * a sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot redirect the untouched-buffer
 * check at a foreign user page.  A poison_seed of 0 means the
 * sanitise-time gate refused to stamp poison for this call (NULL
 * mnt_id) and the post handler must no-op the untouched-buffer check.
 */
#define NAME_TO_HANDLE_AT_POST_STATE_MAGIC	0x4E544841UL	/* "NTHA" */
struct name_to_handle_at_post_state {
	unsigned long magic;
	unsigned long mnt_id;
	uint64_t poison_seed;
};

static void sanitise_name_to_handle_at(struct syscallrecord *rec)
{
	struct file_handle *fh;
	struct name_to_handle_at_post_state *snap;
	int *mnt_id;
	void *pathname;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	/* Allocate enough for the handle struct plus max handle data. */
	fh = (struct file_handle *) get_writable_address(sizeof(*fh) + MAX_HANDLE_SZ);
	if (fh == NULL)
		return;

	switch (rnd_modulo_u32(3)) {
	case 0: fh->handle_bytes = 0; break;		/* query size needed */
	case 1: fh->handle_bytes = MAX_HANDLE_SZ; break;	/* typical */
	default: fh->handle_bytes = rnd_modulo_u32(256); break;	/* boundary */
	}

	mnt_id = (int *) get_writable_address(sizeof(*mnt_id));
	if (mnt_id == NULL)
		return;

	pathname = get_writable_address(256);
	if (pathname == NULL)
		return;

	rec->a2 = (unsigned long) pathname;
	rec->a3 = (unsigned long) fh;
	rec->a4 = (unsigned long) mnt_id;

	avoid_shared_buffer_inout(&rec->a3, sizeof(struct file_handle) + MAX_HANDLE_SZ);
	avoid_shared_buffer_out(&rec->a4, sizeof(int));

	/*
	 * Snapshot the mnt_id user pointer for the post oracle.  Without
	 * this the post handler reads rec->a4 at post-time, when a sibling
	 * syscall may have scribbled the slot -- looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original
	 * value user-buffer pointer, so the untouched-buffer memcmp would
	 * run against a foreign allocation.  post_state is private to the
	 * post handler.  post_state_install pairs the rec->post_state
	 * assign with the ownership-table register so the observable
	 * window between the two is closed; post_name_to_handle_at() will
	 * then gate the snap through post_state_claim_owned() and prove
	 * ownership before dereferencing any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = NAME_TO_HANDLE_AT_POST_STATE_MAGIC;
	snap->mnt_id = rec->a4;
	/*
	 * Stamp a per-call poison pattern into the mnt_id out-buffer the
	 * kernel is about to fill.  The post handler asks
	 * check_output_struct_user_or_skip() whether the pattern survived
	 * intact; if it did on a success return the kernel wrote zero
	 * bytes despite reporting success -- a torn copy_to_user, a
	 * "return 0 before fill" early-exit, or a mis-wired compat
	 * wrapper.  Done after avoid_shared_buffer_out() so the poison
	 * lands on the final buffer the kernel will see (the relocation
	 * may have swapped rec->a4 for a fresh page).
	 *
	 * Skip the stamp when rec->a4 is 0: ARG_ADDRESS is nullable so
	 * avoid_shared_buffer_out() can leave the slot as NULL, and
	 * writing through NULL would SIGSEGV inside poison_output_struct.
	 * The syscall will -EFAULT (or otherwise fail the copy-out) and
	 * the poison_seed == 0 gate in the post handler skips the check.
	 */
	if (rec->a4 != 0)
		snap->poison_seed = poison_output_struct((void *)(unsigned long) rec->a4,
							 sizeof(int), 0);
	post_state_install(rec, snap);
}

/*
 * Post-derived secondary-object registrar wired via
 * .ret_objtype_via_post.  name_to_handle_at writes a struct
 * file_handle out through *handle (rec->a3) and a mnt_id out through
 * *mnt_id (rec->a4); both are inputs an open_by_handle_at consumer
 * needs to round-trip back into an fd.  Neither output has a
 * registerable trinity object type today -- the enum has no
 * OBJ_FILE_HANDLE / OBJ_MNT_ID slot -- so the hook is wired as the
 * future landing site once those object types and an
 * open_by_handle_at consumer side are added.  The retval gate is in
 * place so a follow-up extension does not have to re-derive the
 * success contract.
 */
static void post_name_to_handle_at_record(struct syscallrecord *rec)
{
	if ((long) rec->retval != 0)
		return;

	/*
	 * Reserved: future expansion stashes (handle, mnt_id) into an
	 * OBJ_FILE_HANDLE pool here.  Until that type lands the hook
	 * intentionally falls through with no side effect.
	 */
}

/*
 * Untouched-buffer oracle: sanitise stamps a per-call poison pattern
 * into the mnt_id out-int before the syscall runs; on a success return
 * the post handler asks check_output_struct_user_or_skip() whether the
 * pattern survived intact.  If it did, the kernel wrote zero bytes to
 * *mnt_id despite reporting success -- a torn copy_to_user, a
 * "return 0 before fill" early-exit, or a mis-wired compat wrapper.
 * name_to_handle_at contracts to write both *handle and *mnt_id on a
 * zero return, so a survived poison on the mnt_id side alone is enough
 * to flag the miss.  Bumps the shared post_handler_untouched_out_buf
 * counter.  Expected low hit-rate: success needs a resolvable path so
 * most calls -ENOENT before ever reaching the copy-out; the oracle is
 * still valid because a survived poison after a zero return is
 * unambiguous.
 *
 * This runs alongside post_name_to_handle_at_record (wired via
 * .ret_objtype_via_post) -- both slots fire independently; the record
 * hook stays as the future OBJ_FILE_HANDLE landing site.
 */
static void post_name_to_handle_at(struct syscallrecord *rec)
{
	struct name_to_handle_at_post_state *snap;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, NAME_TO_HANDLE_AT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * name_to_handle_at returns 0 on success; -EOVERFLOW when
	 * handle_bytes was too small still writes mnt_id but is not a
	 * zero return, so gate strictly on retval == 0 to match the
	 * "success contract wrote nothing" defect shape.  Rettype is
	 * RET_ZERO_SUCCESS but the framework does not skip the post
	 * handler on failure, so the explicit gate stands.
	 */
	if ((long) rec->retval != 0)
		goto out_release;

	if (snap->poison_seed == 0)
		goto out_release;

	if (snap->mnt_id == 0)
		goto out_release;

	if (check_output_struct_user_or_skip((void *)(unsigned long) snap->mnt_id,
					     sizeof(int), snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_name_to_handle_at = {
	.name = "name_to_handle_at",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "name", [2] = "handle", [3] = "mnt_id", [4] = "flag" },
	.arg_params[4].list = ARGLIST(name_to_handle_at_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_name_to_handle_at,
	.post = post_name_to_handle_at,
	.ret_objtype_via_post = post_name_to_handle_at_record,
};
