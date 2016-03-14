/*
 * SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
 */
#include <stdlib.h>
#include <linux/ioctl.h>
#include <linux/major.h>
#include "ioctls.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
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
		switch (rnd() % 3) {
		case 0:	rec->a3 = rand32();
			break;
		case 1:	rec->a3 = (unsigned long) get_non_null_address();
			break;
		case 2:	grp = get_random_ioctl_group();
			grp->sanitise(grp, rec);
			break;
		}
	}
}

struct syscallentry syscall_ioctl = {
	.name = "ioctl",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "cmd",
	.arg3name = "arg",
	.sanitise = sanitise_ioctl,
	.flags = NEED_ALARM | IGNORE_ENOSYS,
};
