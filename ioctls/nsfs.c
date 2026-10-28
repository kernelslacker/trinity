/*
 * The ioctls of an nsfs file (ns_ioctl() in fs/nsfs.c).  Namespace files reach
 * a child's pools as what a pidfs getter returns and as the result of any open
 * that lands on one; nothing opens one for a pool, and no fd_test of another
 * group claims one.
 */

#include <linux/ioctl.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "ioctls.h"
#include "kernel/nsfs.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

#ifndef NSFS_MAGIC
#define NSFS_MAGIC	0x6e736673
#endif

/* The most a pid can be: PID_MAX_LIMIT in include/linux/threads.h. */
#define PID_MAX_LIMIT	(4 * 1024 * 1024)

/*
 * NS_GET_MNTNS_ID and NS_GET_ID write a u64 and the mount namespace
 * requests a struct mnt_ns_info, which these pin to what the requests
 * encode.  The pid translations encode an int, but their arg is a pid
 * number, not a pointer, and NS_GET_OWNER_UID encodes nothing.
 */
IOCTL_SIZE_ASSERT(NS_GET_MNTNS_ID, __u64);
IOCTL_SIZE_ASSERT(NS_GET_ID, __u64);
IOCTL_SIZE_ASSERT(NS_MNT_GET_INFO, struct mnt_ns_info);

bool fd_is_nsfs(int fd)
{
	struct statfs sfs;

	return fstatfs(fd, &sfs) == 0 && sfs.f_type == NSFS_MAGIC;
}

/*
 * A namespace file is a regular file with no size (nsfs_init_inode()), so
 * the fstatfs() only has to be asked for those, which keeps it off most of
 * the regular files the pools hold.
 */
static int nsfs_fd_test(int fd, const struct stat *st)
{
	if (!S_ISREG(st->st_mode) || st->st_size != 0)
		return -1;
	return fd_is_nsfs(fd) ? 0 : -1;
}

/*
 * ns_ioctl() answers -ENOIOCTLCMD (-ENOTTY) to a cmd it does not know, and
 * to a mount namespace request whose encoded struct is under 16 bytes
 * (nsfs_ioctl_valid()); the size is part of the cmd, so it is drawn here, one
 * call in 32 under 16.  The kernel copies out no more than its own 16 bytes
 * of struct mnt_ns_info, so a buffer of that size serves any size.
 *
 * What the requests take as their arg: the pid translations a pid number,
 * which find_task_by_pid_ns() and find_task_by_vpid() look up as it is
 * (never the pointer the encoding of an int suggests), so this process's
 * pid half the time and 1 one time in eight, which a translation can find,
 * and the rest numbers that find no task; NS_GET_OWNER_UID,
 * NS_GET_MNTNS_ID, NS_GET_ID and NS_MNT_GET_INFO a pointer the kernel
 * writes through, built here for all four, since the picker has none for an
 * _IO() request and the encoding of the others says only how long it is,
 * and NULL one call in 32, for the -EINVAL and the -EFAULT the kernel has
 * for it.  NS_GET_NSTYPE takes no arg.
 */
static void nsfs_sanitise(const struct ioctl_group *grp,
			  struct syscallrecord *rec)
{
	size_t len = 0;

	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case NS_GET_OWNER_UID:
		len = sizeof(uid_t);
		break;
	case NS_GET_MNTNS_ID:
	case NS_GET_ID:
		len = sizeof(__u64);
		break;
	case NS_MNT_GET_INFO:
		len = sizeof(struct mnt_ns_info);
		switch (rnd_modulo_u32(32)) {
		case 0:
			rec->a2 = _IOC(_IOC_READ, NSIO, _IOC_NR(NS_MNT_GET_INFO),
				       rnd_modulo_u32(MNT_NS_INFO_SIZE_VER0));
			break;
		case 1:
		case 2:
		case 3:
			rec->a2 = _IOC(_IOC_READ, NSIO, _IOC_NR(NS_MNT_GET_INFO),
				       MNT_NS_INFO_SIZE_VER0 +
				       rnd_modulo_u32(_IOC_SIZEMASK + 1 -
						      MNT_NS_INFO_SIZE_VER0));
			break;
		default:
			break;
		}
		break;
	case NS_GET_PID_FROM_PIDNS:
	case NS_GET_TGID_FROM_PIDNS:
	case NS_GET_PID_IN_PIDNS:
	case NS_GET_TGID_IN_PIDNS:
		switch (rnd_modulo_u32(8)) {
		case 0:
			rec->a3 = 1;
			break;
		case 1:
			rec->a3 = 1 + rnd_modulo_u32(PID_MAX_LIMIT);
			break;
		case 2:
			rec->a3 = 0;
			break;
		case 3:
			rec->a3 = rnd_u32();
			break;
		default:
			rec->a3 = getpid();
			break;
		}
		break;
	}

	if (len != 0)
		rec->a3 = ONE_IN(32) ? 0 :
			  (unsigned long) get_writable_address(len);
}

static const struct ioctl nsfs_ioctls[] = {
	IOCTL(NS_GET_NSTYPE),
	IOCTL(NS_GET_OWNER_UID),
	IOCTL(NS_GET_MNTNS_ID),
	IOCTL(NS_GET_PID_FROM_PIDNS),
	IOCTL(NS_GET_TGID_FROM_PIDNS),
	IOCTL(NS_GET_PID_IN_PIDNS),
	IOCTL(NS_GET_TGID_IN_PIDNS),
	IOCTL(NS_MNT_GET_INFO),
	IOCTL(NS_GET_ID),
};

static const struct ioctl_group nsfs_grp = {
	.name = "nsfs",
	.fd_test = nsfs_fd_test,
	.sanitise = nsfs_sanitise,
	.ioctls = nsfs_ioctls,
	.ioctls_cnt = ARRAY_SIZE(nsfs_ioctls),
};

REG_IOCTL_GROUP(nsfs_grp)
