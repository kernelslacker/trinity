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
};

/*
 * MFD_EXEC and MFD_NOEXEC_SEAL are mutually exclusive — the kernel
 * mode-validation in memfd_create() returns -EINVAL if both are set.
 * Keep them out of the bitmask pool above and pick at most one here,
 * mirroring the mmap_excl_flags / type-bit pattern in syscalls/mmap.c.
 * Index 0 is "neither", so a third of memfd_create calls go in with
 * the kernel's default exec semantics.
 */
static unsigned long memfd_create_modes[] = {
	0, MFD_EXEC, MFD_NOEXEC_SEAL,
};

static void sanitise_memfd_create(struct syscallrecord *rec)
{
	/*
	 * Defence in depth: even though memfd_create_flags no longer
	 * contains the exclusive bits, future ARG_LIST tweaks or kernel
	 * UAPI additions could reintroduce them.  Mask before OR-ing the
	 * curated mode in.
	 */
	rec->a2 &= ~(MFD_EXEC | MFD_NOEXEC_SEAL);
	rec->a2 |= RAND_ARRAY(memfd_create_modes);

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
