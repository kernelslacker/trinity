/*
 * SYSCALL_DEFINE2(memfd_create, const char __user *, uname, unsigned int, flag
 */

#include <stdio.h>

#include "publish_resource.h"
#include "random.h"
#include "sanitise.h"
#include "memfd.h"
#include "compat.h"
#include "hugepages.h"
#include "utils.h"

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

/*
 * Generate a curated uname for memfd_create.  ARG_NON_NULL_ADDRESS
 * hands us a random writable region with no NUL guarantee, so the
 * kernel-side strndup_user(NAME_MAX) call almost always errors out
 * before the memfd init paths run.  Bias the call toward valid short
 * basenames (the common case the kernel actually allocates a memfd
 * for) while still covering the empty-string, slash-contains,
 * near-max-length and high-bit-byte edge shapes.
 */
static char *memfd_create_pick_uname(void)
{
	char *name;
	size_t name_len;
	size_t i;

	switch (rnd_modulo_u32(8)) {
	case 0: /* empty string — kernel rejects with -EINVAL */
		name = zmalloc_tracked(1);
		name[0] = '\0';
		break;
	case 1: /* slash-containing — kernel rejects with -EINVAL */
		name = zmalloc_tracked(8);
		snprintf(name, 8, "a/%c", 'a' + (char)rnd_modulo_u32(26));
		break;
	case 2: /* near-max-length basename */
		name_len = 240 + rnd_modulo_u32(16);
		name = zmalloc_tracked(name_len + 1);
		for (i = 0; i < name_len; i++)
			name[i] = 'a' + (char)rnd_modulo_u32(26);
		name[name_len] = '\0';
		break;
	case 3: /* high-bit bytes — exercises strndup_user UTF-8 paths */
		name = zmalloc_tracked(8);
		for (i = 0; i < 7; i++)
			name[i] = (char)(0x80 | rnd_modulo_u32(0x80));
		name[7] = '\0';
		break;
	default: /* short ASCII basename — most common, kernel accepts */
		name_len = 1 + rnd_modulo_u32(15);
		name = zmalloc_tracked(name_len + 1);
		for (i = 0; i < name_len; i++)
			name[i] = 'a' + (char)rnd_modulo_u32(26);
		name[name_len] = '\0';
		break;
	}
	return name;
}

static void sanitise_memfd_create(struct syscallrecord *rec)
{
	/*
	 * Override the ARG_NON_NULL_ADDRESS uname with a curated buffer
	 * so the kernel ingest path doesn't reject the call up front on
	 * a missing NUL within NAME_MAX bytes.  ARG_NON_NULL_ADDRESS
	 * stays in the argtype as a fallback against a NULL rec->a1.
	 */
	rec->a1 = (unsigned long) memfd_create_pick_uname();

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
	int fd = rec->retval;

	if (fd < 0)
		return;

	struct resource_meta meta = {
		.flags = rec->a2,
		.name = NULL,
	};
	publish_resource(OBJ_FD_MEMFD, fd, &meta);
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
