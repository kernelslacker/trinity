/*
 *  SYSCALL_DEFINE5(name_to_handle_at, int, dfd, const char __user *, name,
 *	struct file_handle __user *, handle, int __user *, mnt_id,
 *	int, flag)
 */
#include <fcntl.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "compat.h"

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

static void sanitise_name_to_handle_at(struct syscallrecord *rec)
{
	struct file_handle *fh;
	int *mnt_id;
	void *pathname;

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
	.ret_objtype_via_post = post_name_to_handle_at_record,
};
