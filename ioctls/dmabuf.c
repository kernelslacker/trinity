/* dma-buf ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/dma-buf.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ioctls.h"
#include "utils.h"

/*
 * dma-buf fds are anonymous: they have no /dev/ node and no st_rdev that
 * we could match via the devtype/devs[] path.  They are created by GPU,
 * V4L2, dma-heap and other subsystems and handed out as anon_inode fds.
 * The reliable userspace identifier is the readlink target of
 * /proc/self/fd/<fd>, which is "anon_inode:dmabuf" for any dma-buf fd.
 */
static int dmabuf_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	char path[64];
	char target[64];
	ssize_t n;

	(void) snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	n = readlink(path, target, sizeof(target) - 1);
	if (n < 0)
		return -1;
	target[n] = '\0';

	if (strcmp(target, "anon_inode:dmabuf") == 0)
		return 0;
	return -1;
}

static const struct ioctl dmabuf_ioctls[] = {
#ifdef DMA_BUF_IOCTL_SYNC
	IOCTL(DMA_BUF_IOCTL_SYNC),
#endif
#ifdef DMA_BUF_SET_NAME_A
	IOCTL(DMA_BUF_SET_NAME_A),
#endif
#ifdef DMA_BUF_SET_NAME_B
	IOCTL(DMA_BUF_SET_NAME_B),
#endif
#ifdef DMA_BUF_IOCTL_EXPORT_SYNC_FILE
	IOCTL(DMA_BUF_IOCTL_EXPORT_SYNC_FILE),
#endif
#ifdef DMA_BUF_IOCTL_IMPORT_SYNC_FILE
	IOCTL(DMA_BUF_IOCTL_IMPORT_SYNC_FILE),
#endif
};

static const struct ioctl_group dmabuf_grp = {
	.name = "dmabuf",
	.fd_test = dmabuf_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = dmabuf_ioctls,
	.ioctls_cnt = ARRAY_SIZE(dmabuf_ioctls),
};

REG_IOCTL_GROUP(dmabuf_grp)
