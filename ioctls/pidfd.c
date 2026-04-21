/* pidfd ioctl fuzzing — PIDFS namespace getters and PIDFD_GET_INFO */

#include <linux/ioctl.h>
#include <linux/types.h>

#include "ioctls.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

/*
 * Kernel headers before 6.9 lack the pidfs ioctl magic and all ten
 * namespace-getter commands; guard the whole batch on the first symbol.
 */
#ifndef PIDFD_GET_CGROUP_NAMESPACE
# ifndef PIDFS_IOCTL_MAGIC
#  define PIDFS_IOCTL_MAGIC                    0xFF
# endif
# define PIDFD_GET_CGROUP_NAMESPACE            _IO(PIDFS_IOCTL_MAGIC, 1)
# define PIDFD_GET_IPC_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 2)
# define PIDFD_GET_MNT_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 3)
# define PIDFD_GET_NET_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 4)
# define PIDFD_GET_PID_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 5)
# define PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE  _IO(PIDFS_IOCTL_MAGIC, 6)
# define PIDFD_GET_TIME_NAMESPACE              _IO(PIDFS_IOCTL_MAGIC, 7)
# define PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 8)
# define PIDFD_GET_USER_NAMESPACE              _IO(PIDFS_IOCTL_MAGIC, 9)
# define PIDFD_GET_UTS_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 10)
#endif

/*
 * Linux 6.13 added PIDFD_INFO_* flags as a unit; guard all five on the
 * first flag.
 */
#ifndef PIDFD_INFO_PID
# define PIDFD_INFO_PID      (1UL << 0)
# define PIDFD_INFO_CREDS    (1UL << 1)
# define PIDFD_INFO_CGROUPID (1UL << 2)
# define PIDFD_INFO_EXIT     (1UL << 3)
# define PIDFD_INFO_COREDUMP (1UL << 4)
#endif

/*
 * struct pidfd_info and PIDFD_GET_INFO also landed in Linux 6.13.
 */
#ifndef PIDFD_GET_INFO
struct pidfd_info {
	__u64 mask;
	__u64 cgroupid;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 ruid;
	__u32 rgid;
	__u32 euid;
	__u32 egid;
	__u32 suid;
	__u32 sgid;
	__u32 fsuid;
	__u32 fsgid;
	__s32 exit_code;
	__u32 coredump_mask;
	__u32 __spare1;
};
# define PIDFD_GET_INFO _IOWR(PIDFS_IOCTL_MAGIC, 11, struct pidfd_info)
#endif

static int pidfd_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct list_head *globallist, *node;
	struct object *obj;

	globallist = shm->global_objects[OBJ_FD_PIDFD].list;
	list_for_each(node, globallist) {
		obj = (struct object *) node;
		if (obj->pidfdobj.fd == fd)
			return 0;
	}

	return -1;
}

static void pidfd_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	struct pidfd_info *info;
	static const unsigned long info_flags[] = {
		PIDFD_INFO_PID,
		PIDFD_INFO_CREDS,
		PIDFD_INFO_CGROUPID,
		PIDFD_INFO_EXIT,
		PIDFD_INFO_COREDUMP,
	};

	pick_random_ioctl(grp, rec);

	if (rec->a2 != PIDFD_GET_INFO)
		return;

	info = (struct pidfd_info *) get_writable_struct(sizeof(*info));
	if (!info)
		return;
	info->mask = set_rand_bitmask(ARRAY_SIZE(info_flags), info_flags);
	rec->a3 = (unsigned long) info;
}

static const struct ioctl pidfd_ioctls[] = {
	IOCTL(PIDFD_GET_CGROUP_NAMESPACE),
	IOCTL(PIDFD_GET_IPC_NAMESPACE),
	IOCTL(PIDFD_GET_MNT_NAMESPACE),
	IOCTL(PIDFD_GET_NET_NAMESPACE),
	IOCTL(PIDFD_GET_PID_NAMESPACE),
	IOCTL(PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE),
	IOCTL(PIDFD_GET_TIME_NAMESPACE),
	IOCTL(PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE),
	IOCTL(PIDFD_GET_USER_NAMESPACE),
	IOCTL(PIDFD_GET_UTS_NAMESPACE),
	IOCTL(PIDFD_GET_INFO),
};

static const struct ioctl_group pidfd_grp = {
	.name = "pidfd",
	.fd_test = pidfd_fd_test,
	.sanitise = pidfd_sanitise,
	.ioctls = pidfd_ioctls,
	.ioctls_cnt = ARRAY_SIZE(pidfd_ioctls),
};

REG_IOCTL_GROUP(pidfd_grp)
