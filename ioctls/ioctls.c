/* trinity ioctl() support routines */

#include <linux/ioctl.h>
#include <string.h>
#include <stdio.h>

#include "files.h"
#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"	// ARRAY_SIZE

#define IOCTL_GROUPS_MAX 48

static const struct ioctl_group *grps[IOCTL_GROUPS_MAX];
static int grps_cnt;

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

	++grps_cnt;
}

static const struct ioctl_group * match_ioctl(int fd, struct stat *stbuf, int matchcount)
{
	int i;
	unsigned int retries = 0;

retry:
	for (i = 0; i < grps_cnt; ++i) {
		if (grps[i]->fd_test) {
			if (grps[i]->fd_test(fd, stbuf) == 0) {
				/* if this is the only match, just do it. */
				if (matchcount == 1) {
					return grps[i];
				} else {
					if (RAND_BOOL())
						return grps[i];
				}
			}
		}
	}

	// If we get here we failed the RAND_BOOL too many times.
	if (++retries < 1000)
		goto retry;

	/* Exhausted retries — return the first match. */
	for (i = 0; i < grps_cnt; ++i) {
		if (grps[i]->fd_test && grps[i]->fd_test(fd, stbuf) == 0)
			return grps[i];
	}
	return NULL;
}

const struct ioctl_group *find_ioctl_group(int fd)
{
	const char *devname;
	struct stat stbuf;
	int i;
	size_t j;
	int matchcount = 0;

	if (fstat(fd, &stbuf) < 0)
		return NULL;

	/* Find out if >1 ioctl with an fd_test matches this fd type. */
	for (i = 0; i < grps_cnt; ++i) {
		if (grps[i]->fd_test) {
			if (grps[i]->fd_test(fd, &stbuf) == 0)
				matchcount++;
		}
	}

	if (matchcount > 0)
		return match_ioctl(fd, &stbuf, matchcount);

	/* We don't have an fd_test, so try matching on type & devname */
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

		if (stbuf.st_rdev == 0)
			return NULL;

		devname = map_dev(stbuf.st_rdev, stbuf.st_mode);
		if (!devname)
			return NULL;

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

static unsigned long random_ioctl_arg(void)
{
	if (RAND_BOOL()) {
		return (unsigned long) rand64();
	} else {
		void *page;

		page = get_writable_address(page_size);
		generate_random_page(page);

		return (unsigned long) page;
	}
}

/*
 * Pick an arg shape for the given ioctl request based on the
 * _IOC_DIR / _IOC_SIZE fields baked into the request number.  Any
 * ioctl defined via _IO()/_IOR()/_IOW()/_IOWR() (the bulk of trinity's
 * tables — V4L2, btrfs, binder, DRM, vhost, ...) carries enough
 * information here to choose between a scalar and a properly-sized
 * pointer, which is most of what the kernel checks before dispatching
 * into real handler logic.
 *
 * Legacy raw-constant ioctls (TCGETS-style 0x5401, sockios, ...) do
 * not encode anything reliable: their _IOC_TYPE may collide with an
 * ASCII char, their _IOC_SIZE bits are part of the magic number, and
 * their _IOC_DIR bits are typically zero.  We catch the obvious case
 * (_IOC_TYPE == 0) and defer to the historical coin flip; the rest
 * land in the dir==NONE branch and get handed a scalar, which matches
 * one of the two outcomes the old generator already produced.  An
 * EFAULT-probe pass is the proper fix for the legacy surface and is
 * tracked as a separate change.
 */
static unsigned long ioctl_arg_for_request(unsigned int request)
{
	unsigned int dir, size;
	void *buf;

	if (_IOC_TYPE(request) == 0)
		return random_ioctl_arg();

	dir = _IOC_DIR(request);
	if (dir == _IOC_NONE)
		return (unsigned long) rand64();

	size = _IOC_SIZE(request);
	if (size == 0 || size > page_size)
		size = page_size;

	buf = get_writable_address(size);
	if (buf == NULL)
		return random_ioctl_arg();

	/*
	 * _IOC_WRITE means userland writes / kernel reads (the _IOW and
	 * _IOWR families).  Without meaningful contents the kernel
	 * usually rejects on first-field validation, so seed the buffer
	 * with random bytes.  Pure _IOC_READ ioctls have the kernel
	 * writing back into the buffer — we just needed a writable
	 * destination address.
	 */
	if (dir & _IOC_WRITE)
		generate_rand_bytes((unsigned char *) buf, size);

	return (unsigned long) buf;
}

void pick_random_ioctl(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	int ioctlnr;
	unsigned int request;

	ioctlnr = rand() % grp->ioctls_cnt;
	request = grp->ioctls[ioctlnr].request;

	rec->a2 = request;
	rec->a3 = ioctl_arg_for_request(request);
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
	avoid_shared_buffer(&rec->a3, page_size);
	avoid_shared_buffer(&rec->a4, page_size);
	avoid_shared_buffer(&rec->a5, page_size);
	avoid_shared_buffer(&rec->a6, page_size);
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
