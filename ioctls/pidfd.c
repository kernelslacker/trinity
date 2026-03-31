/* pidfd ioctl fuzzing — PIDFS namespace getters and PIDFD_GET_INFO */

#include <linux/ioctl.h>
#include <linux/types.h>

#include "ioctls.h"
#include "objects.h"
#include "shm.h"
#include "utils.h"

/*
 * pidfd.h may not be available on older toolchains, so define the
 * ioctl magic and commands locally if the header is missing.
 */
#ifndef PIDFS_IOCTL_MAGIC
#define PIDFS_IOCTL_MAGIC 0xFF
#endif

#ifndef PIDFD_GET_CGROUP_NAMESPACE
#define PIDFD_GET_CGROUP_NAMESPACE            _IO(PIDFS_IOCTL_MAGIC, 1)
#endif
#ifndef PIDFD_GET_IPC_NAMESPACE
#define PIDFD_GET_IPC_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 2)
#endif
#ifndef PIDFD_GET_MNT_NAMESPACE
#define PIDFD_GET_MNT_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 3)
#endif
#ifndef PIDFD_GET_NET_NAMESPACE
#define PIDFD_GET_NET_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 4)
#endif
#ifndef PIDFD_GET_PID_NAMESPACE
#define PIDFD_GET_PID_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 5)
#endif
#ifndef PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE
#define PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE  _IO(PIDFS_IOCTL_MAGIC, 6)
#endif
#ifndef PIDFD_GET_TIME_NAMESPACE
#define PIDFD_GET_TIME_NAMESPACE              _IO(PIDFS_IOCTL_MAGIC, 7)
#endif
#ifndef PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE
#define PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 8)
#endif
#ifndef PIDFD_GET_USER_NAMESPACE
#define PIDFD_GET_USER_NAMESPACE              _IO(PIDFS_IOCTL_MAGIC, 9)
#endif
#ifndef PIDFD_GET_UTS_NAMESPACE
#define PIDFD_GET_UTS_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 10)
#endif

/*
 * PIDFD_GET_INFO takes a struct pidfd_info pointer.  We don't need the
 * struct definition here — the fuzzer just passes random data — but we
 * do need the ioctl number.  Define a minimal placeholder if the real
 * header doesn't provide it.
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
	struct {
		__u32 coredump_mask;
		__u32 coredump_signal;
	};
	__u64 supported_mask;
};
#define PIDFD_GET_INFO _IOWR(PIDFS_IOCTL_MAGIC, 11, struct pidfd_info)
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
	.sanitise = pick_random_ioctl,
	.ioctls = pidfd_ioctls,
	.ioctls_cnt = ARRAY_SIZE(pidfd_ioctls),
};

REG_IOCTL_GROUP(pidfd_grp)
