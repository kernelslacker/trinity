/*
 * SYSCALL_DEFINE2(memfd_create, const char __user *, uname, unsigned int, flag
 */

#include "objects.h"
#include "sanitise.h"
#include "memfd.h"
#include "compat.h"

static unsigned long memfd_create_flags[] = {
	MFD_CLOEXEC, MFD_ALLOW_SEALING, MFD_HUGETLB,
	MFD_NOEXEC_SEAL, MFD_EXEC,
};

static void post_memfd_create(struct syscallrecord *rec)
{
	struct object *new;
	int fd = rec->retval;

	if (fd == -1)
		return;

	new = alloc_object();
	new->memfdobj.fd = fd;
	new->memfdobj.name = NULL;
	new->memfdobj.flags = rec->a2;
	add_object(new, OBJ_LOCAL, OBJ_FD_MEMFD);
}

struct syscallentry syscall_memfd_create = {
	.name = "memfd_create",
	.num_args = 2,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_LIST },
	.argname = { [0] = "uname", [1] = "flag" },
	.arg_params[1].list = ARGLIST(memfd_create_flags),
	.rettype = RET_FD,
	.post = post_memfd_create,
	.group = GROUP_VFS,
};
