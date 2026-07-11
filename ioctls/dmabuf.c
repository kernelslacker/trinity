/* dma-buf ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/dma-buf.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>

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

/*
 * Compile-time: every fixed-shape dma-buf ioctl command in the table
 * below whose arg is a kernel struct must have sizeof(struct)
 * matching the _IOC_SIZE encoded in its request bits.  A mismatch
 * means dma-buf.h moved under us and the request bits now encode a
 * different struct than we're passing (or vice versa) -- either
 * short of the kernel's copy_from_user() / copy_to_user() or past
 * it.  Per-cmd #ifdef guards mirror the ioctl-table wrapping so
 * builds against older uapi headers that predate a command still
 * compile.
 *
 * DMA_BUF_SET_NAME_A and DMA_BUF_SET_NAME_B encode a bare __u32 and
 * __u64 respectively (two spellings of the same DMA_BUF_SET_NAME
 * request that took a plain string pointer historically).  Both are
 * intentionally absent -- asserting sizeof(struct) against a scalar
 * would be the wrong shape of check.
 */
#ifdef DMA_BUF_IOCTL_SYNC
_Static_assert(sizeof(struct dma_buf_sync) ==
	       _IOC_SIZE(DMA_BUF_IOCTL_SYNC),
	       "dma_buf_sync size vs _IOC_SIZE mismatch");
#endif
#ifdef DMA_BUF_IOCTL_EXPORT_SYNC_FILE
_Static_assert(sizeof(struct dma_buf_export_sync_file) ==
	       _IOC_SIZE(DMA_BUF_IOCTL_EXPORT_SYNC_FILE),
	       "dma_buf_export_sync_file size vs _IOC_SIZE mismatch");
#endif
#ifdef DMA_BUF_IOCTL_IMPORT_SYNC_FILE
_Static_assert(sizeof(struct dma_buf_import_sync_file) ==
	       _IOC_SIZE(DMA_BUF_IOCTL_IMPORT_SYNC_FILE),
	       "dma_buf_import_sync_file size vs _IOC_SIZE mismatch");
#endif

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
