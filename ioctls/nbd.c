/* /dev/nbdN block device ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/major.h>
#include <linux/nbd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "ioctls.h"
#include "utils.h"

/*
 * /dev/nbdN are block devices on NBD_MAJOR (43).  Match block fds by
 * major rather than by devname so we don't fire NBD_* ioctls at other
 * block drivers that happen to share a name prefix.
 *
 * All NBD_* ioctls share the 0xab type byte and are gated by
 * CAP_SYS_ADMIN in the kernel handler (drivers/block/nbd.c
 * nbd_ioctl()).  Bodies are scalar config->field = arg assignments
 * (size, blksize, timeout, flags...), so no per-ioctl sanitiser is
 * required -- trinity's existing random a3 fill is the right shape.
 *
 * NBD_DO_IT is intentionally omitted (mirroring the SG_SCSI_RESET
 * exclusion in ioctls/sg.c): it enters wait_event_interruptible() in
 * nbd_start_device_ioctl() while still holding nbd->config_lock, and
 * will hang the trinity child indefinitely if a paired socket fd from
 * the fd pool happens to validate.  Lose nothing actionable -- the
 * start-device path is overwhelmingly userspace-handshake-driven and
 * is also reachable via the netlink genl family.
 */

static const struct ioctl nbd_ioctls[] = {
#ifdef NBD_SET_SOCK
	IOCTL(NBD_SET_SOCK),
#endif
#ifdef NBD_SET_BLKSIZE
	IOCTL(NBD_SET_BLKSIZE),
#endif
#ifdef NBD_SET_SIZE
	IOCTL(NBD_SET_SIZE),
#endif
#ifdef NBD_CLEAR_SOCK
	IOCTL(NBD_CLEAR_SOCK),
#endif
#ifdef NBD_CLEAR_QUE
	IOCTL(NBD_CLEAR_QUE),
#endif
#ifdef NBD_PRINT_DEBUG
	IOCTL(NBD_PRINT_DEBUG),
#endif
#ifdef NBD_SET_SIZE_BLOCKS
	IOCTL(NBD_SET_SIZE_BLOCKS),
#endif
#ifdef NBD_DISCONNECT
	IOCTL(NBD_DISCONNECT),
#endif
#ifdef NBD_SET_TIMEOUT
	IOCTL(NBD_SET_TIMEOUT),
#endif
#ifdef NBD_SET_FLAGS
	IOCTL(NBD_SET_FLAGS),
#endif
};

static int nbd_fd_test(int fd __attribute__((unused)),
		       const struct stat *st)
{
	if (!S_ISBLK(st->st_mode))
		return -1;
	if (major(st->st_rdev) != NBD_MAJOR)
		return -1;
	return 0;
}

static const char *const nbd_devs[] = {
	"nbd",
};

static const struct ioctl_group nbd_grp = {
	.name = "nbd",
	.devtype = DEV_BLOCK,
	.devs = nbd_devs,
	.devs_cnt = ARRAY_SIZE(nbd_devs),
	.fd_test = nbd_fd_test,
	.sanitise = pick_random_ioctl,
	.ioctls = nbd_ioctls,
	.ioctls_cnt = ARRAY_SIZE(nbd_ioctls),
};

REG_IOCTL_GROUP(nbd_grp)
