/* trinity ioctl() support routines */

#include <string.h>
#include <stdio.h>

#include "files.h"
#include "shm.h"
#include "ioctls.h"

#define IOCTL_GROUPS_MAX 32

static const struct ioctl_group *grps[IOCTL_GROUPS_MAX];
static int grps_cnt;

void register_ioctl_group(const struct ioctl_group *grp)
{
	if (grps_cnt == ARRAY_SIZE(grps)) {
		fprintf(stderr, "WARNING: please grow IOCTL_GROUPS_MAX.\n");
		return;
	}

	grps[grps_cnt] = grp;

	++grps_cnt;
}

const struct ioctl_group *find_ioctl_group(int fd)
{
	const char *devname;
	struct stat stbuf;
	int i;
	size_t j;

	if (fstat(fd, &stbuf) < 0)
		return NULL;

	if (stbuf.st_rdev == 0)
		return NULL;

	devname = map_dev(stbuf.st_rdev, stbuf.st_mode);
	if (!devname)
		return NULL;

	for (i=0; i < grps_cnt; ++i) {
		if (grps[i]->fd_test) {
			if (grps[i]->fd_test(fd, &stbuf) == 0)
				return grps[i];
			else
				continue;
		}

		switch (grps[i]->devtype) {
		case DEV_MISC:
			/* fall through. misc devices are char devices. */
		case DEV_CHAR:
			if (!S_ISCHR(stbuf.st_mode))
				continue;
			break;
		case DEV_BLOCK:
			if (!S_ISBLK(stbuf.st_mode))
				continue;
			break;
		default: break;
		}

		for (j=0; j < grps[i]->devs_cnt; ++j)
			if (strcmp(devname, grps[i]->devs[j]) == 0)
				return grps[i];
	}

	return NULL;
}

const struct ioctl_group *get_random_ioctl_group(void)
{
	if (grps_cnt == 0)
		return NULL;

	return grps[rand() % grps_cnt];
}

void pick_random_ioctl(const struct ioctl_group *grp, int childno)
{
	int ioctlnr;

	ioctlnr = rand() % grp->ioctls_cnt;

	shm->a2[childno] = grp->ioctls[ioctlnr].request;
}
