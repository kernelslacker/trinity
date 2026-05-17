/*
 *  SYSCALL_DEFINE5(name_to_handle_at, int, dfd, const char __user *, name,
 *	struct file_handle __user *, handle, int __user *, mnt_id,
 *	int, flag)
 */
#include <fcntl.h>
#include "random.h"
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

	switch (rand() % 3) {
	case 0: fh->handle_bytes = 0; break;		/* query size needed */
	case 1: fh->handle_bytes = MAX_HANDLE_SZ; break;	/* typical */
	default: fh->handle_bytes = rand() % 256; break;	/* boundary */
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

	avoid_shared_buffer(&rec->a3, sizeof(struct file_handle) + MAX_HANDLE_SZ);
	avoid_shared_buffer(&rec->a4, sizeof(int));
}

struct syscallentry syscall_name_to_handle_at = {
	.name = "name_to_handle_at",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [4] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "name", [2] = "handle", [3] = "mnt_id", [4] = "flag" },
	.arg_params[4].list = ARGLIST(name_to_handle_at_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_name_to_handle_at,
};
