/*
 * SYSCALL_DEFINE2(memfd_create, const char __user *, uname, unsigned int, flag
 */

#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "memfd.h"
#include "compat.h"
#include "hugepages.h"

static unsigned long memfd_create_flags[] = {
	MFD_CLOEXEC, MFD_ALLOW_SEALING, MFD_HUGETLB,
	MFD_NOEXEC_SEAL, MFD_EXEC,
};

static void sanitise_memfd_create(struct syscallrecord *rec)
{
	/*
	 * MFD_HUGE_* shares the MAP_HUGE_SHIFT (26) encoding.  When the
	 * ARG_LIST roll happened to set MFD_HUGETLB, sometimes also pack
	 * a specific log2 size into the upper bits — otherwise the kernel
	 * just uses the default huge page size and the MFD_HUGE_* paths
	 * never fire.
	 */
	if ((rec->a2 & MFD_HUGETLB) && RAND_BOOL())
		rec->a2 |= pick_random_huge_size_encoding();
}

static void post_memfd_create(struct syscallrecord *rec)
{
	struct object *new;
	int fd = rec->retval;

	if ((long)rec->retval < 0)
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
	.ret_objtype = OBJ_FD_MEMFD,
	.sanitise = sanitise_memfd_create,
	.post = post_memfd_create,
	.group = GROUP_VFS,
};
