/*
 * Filesystem / VFS struct-catalog registrations.
 *
 * epoll_ctl, open_by_handle_at, utime and the cmd-discriminated fcntl
 * a3 are struct-pointer slots the generator fills; mount_setattr and
 * open_tree_attr are read only for their ARG_STRUCT_SIZE argument.
 */

#include <stddef.h>
#include <fcntl.h>

#include "config.h"

#include "struct_catalog.h"

#include "kernel/fcntl.h"

/*
 * fcntl arg3 cmd discriminator pools.  Sibling arg a2 (cmd) selects
 * which struct backs the a3 pointer; the discriminator-aware lookup
 * resolves these lists against rec->a2 to pick the right descriptor.
 *
 * fcntl_flock_cmds: every cmd where the kernel reads a struct flock
 * at a3 -- POSIX (F_GETLK / F_SETLK / F_SETLKW), OFD (F_OFD_*) and
 * F_CANCELLK.  The LK64 variants are folded in via the
 * F_GETLK64 != F_GETLK preprocessor gate so 64-bit-clean toolchains
 * (where the LK64 cmd values collapse onto their non-LK64 siblings)
 * don't waste a duplicate-match slot.
 *
 * fcntl_f_owner_ex_cmds: the two cmds where a3 is a struct
 * f_owner_ex pointer.
 */
static const unsigned long fcntl_flock_cmds[] = {
	F_GETLK, F_SETLK, F_SETLKW,
	F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW,
	F_CANCELLK,
#if F_GETLK64 != F_GETLK
	F_GETLK64, F_SETLK64, F_SETLKW64,
#endif
};

static const unsigned long fcntl_f_owner_ex_cmds[] = {
	F_GETOWN_EX, F_SETOWN_EX,
};

const struct syscall_struct_arg struct_catalog_registry_fs[] = {
	/* epoll_ctl(int, int, int, struct epoll_event *) */
	{ "epoll_ctl",		4, &struct_catalog[SC_EPOLL_EVENT] },
	/*
	 * mount_setattr(int dfd, const char *path, unsigned int flags,
	 *               struct mount_attr *uattr, size_t usize)
	 * open_tree_attr(int dfd, const char *filename, unsigned int flags,
	 *                struct mount_attr *uattr, size_t usize)
	 * Both a4 slots are ARG_STRUCT_PTR_IN, but the bespoke sanitisers
	 * (build_mount_attr / sanitise_mount_setattr) own rec->a4 and plant
	 * their own usize at a5, so no schema-aware fill runs.  The rows are
	 * read only by the paired-descriptor lookup behind ARG_STRUCT_SIZE.
	 */
	{ "mount_setattr",	4, &struct_catalog[SC_MOUNT_ATTR] },
	{ "open_tree_attr",	4, &struct_catalog[SC_MOUNT_ATTR] },
	/*
	 * open_by_handle_at(int mountdirfd, struct file_handle *handle, int flags)
	 * a2 (1-indexed) is the file_handle.  Schema-fill produces a coherent
	 * (handle_bytes, handle_type) pair and exercises the kernel's
	 * handle_bytes bounds check when fuzzed past the sized buffer.
	 */
	{ "open_by_handle_at",	2, &struct_catalog[SC_FILE_HANDLE] },
	/*
	 * utime(const char *filename, const struct utimbuf __user *times)
	 * a2 is the INPUT struct utimbuf pointer.  utime has no bespoke
	 * .sanitise; argtype[1] is ARG_STRUCT_PTR_IN, so the times buffer
	 * lands on a dedicated sized buffer filled from the utimbuf layout.
	 */
	{ "utime",		2, &struct_catalog[SC_UTIMBUF] },
	/*
	 * fcntl(int fd, int cmd, ... arg): a3 is cmd-discriminated between
	 * struct flock (fcntl_flock_cmds pool) and struct f_owner_ex
	 * (fcntl_f_owner_ex_cmds pool); unlisted cmds resolve NULL.
	 * sanitise_fcntl() swaps in its own buffer for F_SETLK* and
	 * F_SETOWN_EX; the get cmds keep the generated one.  See
	 * Documentation/struct_catalog.md.
	 */
	{
		"fcntl", 3, &struct_catalog[SC_FLOCK],
		.discrim_arg_idx	= 2,
		.discrim_values		= fcntl_flock_cmds,
		.num_discrim_values	= ARRAY_SIZE(fcntl_flock_cmds),
	},
	{
		"fcntl", 3, &struct_catalog[SC_F_OWNER_EX],
		.discrim_arg_idx	= 2,
		.discrim_values		= fcntl_f_owner_ex_cmds,
		.num_discrim_values	= ARRAY_SIZE(fcntl_f_owner_ex_cmds),
	},
	/* sentinel */
	{ NULL, 0, NULL },
};
