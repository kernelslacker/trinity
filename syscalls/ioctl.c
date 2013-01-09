/*
 * SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
 */
#include <stdlib.h>
#include <linux/ioctl.h>
#include <linux/major.h>

#include "trinity.h"
#include "sanitise.h"
#include "shm.h"

struct ioctl {
	const char *name;
	unsigned int request;
	void (*sanitise)(int childno);
};

const struct ioctl ioctllist[] = {
#include "ioctls/scsi-generic.h"
#include "ioctls/framebuffer.h"
#include "ioctls/console.h"
#include "ioctls/cdrom.h"
#include "ioctls/scsi.h"
#include "ioctls/tty.h"
#include "ioctls/vt.h"
#include "ioctls/socket.h"
#include "ioctls/snd.h"
#include "ioctls/mem.h"
#include "ioctls/sisfb.h"
};

static void generic_sanitise_ioctl(int childno)
{
	unsigned int i;

	/* One time in 50, mangle cmd. */
	if ((rand() % 50)==0) {

		/* mangle the cmd by ORing up to 4 random bits */
		for (i=0; i < (unsigned int)(rand() % 4); i++)
			shm->a2[childno] |= 1L << (rand() % 32);

		/* mangle the cmd by ANDing up to 4 random bits */
		for (i=0; i < (unsigned int)(rand() % 4); i++)
			shm->a2[childno] &= 1L << (rand() % 32);
	}

	/* the argument could mean anything, because ioctl sucks like that. */
	switch (rand() % 2) {
	case 0:	shm->a3[childno] = get_interesting_32bit_value();
		break;

	case 1:	shm->a3[childno] = (unsigned long) page_rand;
		fabricate_onepage_struct(page_rand);
		break;
	default: break;
	}
}

static void sanitise_ioctl(int childno)
{
	int ioctlnr;

	ioctlnr = rand() % ARRAY_SIZE(ioctllist);
	shm->a2[childno] = ioctllist[ioctlnr].request;

	if (ioctllist[ioctlnr].sanitise)
		ioctllist[ioctlnr].sanitise(childno);
	else
		generic_sanitise_ioctl(childno);
}

struct syscall syscall_ioctl = {
	.name = "ioctl",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "cmd",
	.arg3name = "arg",
	.arg3type = ARG_RANDPAGE,
	.sanitise = sanitise_ioctl,
	.flags = NEED_ALARM,
};
