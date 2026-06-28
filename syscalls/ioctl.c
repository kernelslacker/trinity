/*
 * SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
 */
#include <linux/ioctl.h>
#include <linux/major.h>
#include "arch.h"
#include "ioctls.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_ioctl(struct syscallrecord *rec)
{
	const struct ioctl_group *grp;

	if (ONE_IN(100))
		grp = get_random_ioctl_group();
	else
		grp = find_ioctl_group(rec->a1);

	if (grp)
		grp->sanitise(grp, rec);
	else {
		/* if we don't know about this ioctl, the argument could mean anything,
		 * because ioctl sucks like that. Make some shit up.
		 */
		switch (rnd_modulo_u32(3)) {
		case 0:	rec->a3 = rand32();
			break;
		case 1:	rec->a3 = (unsigned long) get_non_null_address();
			break;
		case 2:	grp = get_random_ioctl_group();
			if (grp)
				grp->sanitise(grp, rec);
			break;
		}
	}

	/*
	 * pick_random_ioctl() scrubs rec->a3 against shared_regions[], but
	 * most custom sanitisers run pick_random_ioctl() and then overwrite
	 * a3 with a get_writable_struct()/get_writable_address() pointer.
	 * Those allocators legitimately return addresses inside the global
	 * shared tracker (childdata, stats, kcov buffers, the obj/str
	 * heaps), so a read/write-direction ioctl would copy_to_user back
	 * onto our own bookkeeping.  Re-run the scrub here so the post-
	 * sanitise a3 cannot land in shared_regions[] regardless of which
	 * group ran.
	 */
	avoid_shared_buffer_out(&rec->a3, page_size);
}

struct syscallentry syscall_ioctl = {
	.name = "ioctl",
	.num_args = 3,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fd", [1] = "cmd", [2] = "arg" },
	.sanitise = sanitise_ioctl,
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.group = GROUP_VFS,
};
