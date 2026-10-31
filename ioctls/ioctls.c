/* trinity ioctl() support routines */

#include <linux/ioctl.h>
#include <string.h>

#include "efault_cache.h"
#include "files.h"
#include "ioctls.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"	// ARRAY_SIZE

static const struct ioctl_group *grps[IOCTL_GROUPS_MAX];
static int grps_cnt;

/* The groups that set fd_class and have an fd_test to confirm the fd. */
static const struct ioctl_group *fd_class_grps[IOCTL_GROUPS_MAX];
static int fd_class_grps_cnt;

void register_ioctl_group(const struct ioctl_group *grp)
{
	/* group could be empty e.g. if everything is ifdeffed out */
	if (grp->ioctls_cnt == 0)
		return;

	if (grps_cnt == ARRAY_SIZE(grps)) {
		outputerr("WARNING: please grow IOCTL_GROUPS_MAX.\n");
		return;
	}

	grps[grps_cnt] = grp;
	ioctl_efault_register_group(grp, grps_cnt);

	if (grp->fd_class != ARG_UNDEFINED && grp->fd_test != NULL)
		fd_class_grps[fd_class_grps_cnt++] = grp;

	++grps_cnt;
}

const struct ioctl_group *find_ioctl_group(int fd)
{
	const char *devname;
	struct stat stbuf;
	int matches[IOCTL_GROUPS_MAX];
	int i;
	size_t j;
	int matchcount = 0;

	if (fstat(fd, &stbuf) < 0)
		return NULL;

	/* Collect every fd_test-equipped group that claims this fd. */
	for (i = 0; i < grps_cnt; ++i) {
		if (grps[i]->fd_test) {
			if (grps[i]->fd_test(fd, &stbuf) == 0)
				matches[matchcount++] = i;
		}
	}

	if (matchcount > 0)
		return grps[matches[rnd_modulo_u32(matchcount)]];

	/* We don't have an fd_test, so try matching on type & devname */
	if (stbuf.st_rdev == 0)
		return NULL;

	devname = map_dev(stbuf.st_rdev, stbuf.st_mode);
	if (!devname)
		return NULL;

	for (i = 0; i < grps_cnt; ++i) {
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

	return grps[rnd_modulo_u32(grps_cnt)];
}

const struct ioctl_group *get_random_fd_class_ioctl_group(void)
{
	if (fd_class_grps_cnt == 0)
		return NULL;

	return fd_class_grps[rnd_modulo_u32(fd_class_grps_cnt)];
}

/*
 * Stable index of grp in the registered-groups table.  Constructor
 * registration order is deterministic and identical across all forked
 * children, so the index works as the group half of the EFAULT-probe
 * cache key without needing to hash a pointer that varies between
 * processes.  Linear scan is fine — grps_cnt is at most 64.
 */
int ioctl_group_index(const struct ioctl_group *grp)
{
	int i;

	if (grp == NULL)
		return -1;

	for (i = 0; i < grps_cnt; ++i)
		if (grps[i] == grp)
			return i;
	return -1;
}

void pick_random_ioctl(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	int ioctlnr;
	unsigned int request;

	ioctlnr = rnd_modulo_u32(grp->ioctls_cnt);
	request = grp->ioctls[ioctlnr].request;

	rec->a2 = request;
	rec->a3 = ioctl_arg_for_request(grp, (int) rec->a1, request);
	rec->a4 = random_ioctl_arg();
	rec->a5 = random_ioctl_arg();
	rec->a6 = random_ioctl_arg();

	/*
	 * a3 is the real ioctl arg.  ioctl_arg_for_request() draws from
	 * get_writable_address() which already steers around shared
	 * regions, but keep the defensive scrub so a future refactor
	 * can't quietly expose trinity bookkeeping to a kernel writeback.
	 * a4..a6 still come from the unconstrained generator and need
	 * the scrub directly.
	 */
	avoid_shared_buffer_out(&rec->a3, page_size);
	avoid_shared_buffer_out(&rec->a4, page_size);
	avoid_shared_buffer_out(&rec->a5, page_size);
	avoid_shared_buffer_out(&rec->a6, page_size);
}

void dump_ioctls(void)
{
	int i;
	size_t j;

	for (i=0; i < grps_cnt; ++i) {
		if (grps[i]->name)
			outputerr("- %s:\n", grps[i]->name);
		else if (grps[i]->devtype) {
			if (grps[i]->devtype == DEV_MISC)
				outputerr("- misc devices");
			else if (grps[i]->devtype == DEV_CHAR)
				outputerr("- char devices");
			else if (grps[i]->devtype == DEV_BLOCK)
				outputerr("- block devices");
			for (j=0; j < grps[i]->devs_cnt; ++j)
				outputerr("%s '%s'",
					j == 0 ? "" : ",",
					grps[i]->devs[j]);
			outputerr(":\n");
		} else
			outputerr("- <unknown>:\n");

		for (j=0; j < grps[i]->ioctls_cnt; ++j) {
			outputerr("  - 0x%08x : %s\n",
					grps[i]->ioctls[j].request,
					grps[i]->ioctls[j].name ? : "");
		}
	}
}
