#pragma once

/*
 * Wrapper around <linux/mount.h> that ships #ifndef-guarded fallbacks
 * for the new-mount-API constants (fsopen / fsconfig / fsmount) added
 * after our installed uapi header.  The syscalls themselves are
 * available on every kernel trinity targets (fsopen landed in 5.2);
 * only the symbolic constants may be missing on older build hosts.
 */
#include <linux/mount.h>

#include "kernel/fcntl.h"
#ifndef FSOPEN_CLOEXEC
#define FSOPEN_CLOEXEC		0x00000001
#endif
#ifndef FSMOUNT_CLOEXEC
#define FSMOUNT_CLOEXEC		0x00000001
#endif
#ifndef FSCONFIG_SET_FLAG
#define FSCONFIG_SET_FLAG	0
#endif
#ifndef FSCONFIG_SET_STRING
#define FSCONFIG_SET_STRING	1
#endif
#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE	6
#endif
#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE		1
#define OPEN_TREE_CLOEXEC	O_CLOEXEC
#endif
#ifndef OPEN_TREE_NAMESPACE
#define OPEN_TREE_NAMESPACE	2
#endif
#ifndef FSMOUNT_NAMESPACE
#define FSMOUNT_NAMESPACE	0x00000002
#endif
#ifndef FSPICK_CLOEXEC
#define FSPICK_CLOEXEC		0x00000001
#define FSPICK_SYMLINK_NOFOLLOW	0x00000002
#define FSPICK_NO_AUTOMOUNT	0x00000004
#define FSPICK_EMPTY_PATH	0x00000008
#endif
#ifndef LISTMOUNT_REVERSE
#define LISTMOUNT_REVERSE	(1 << 0)
#endif
#ifndef LSMT_ROOT
#define LSMT_ROOT		0xffffffffffffffff
#endif
#ifndef STATMOUNT_SB_BASIC
#define STATMOUNT_SB_BASIC		0x00000001U
#define STATMOUNT_MNT_BASIC		0x00000002U
#define STATMOUNT_PROPAGATE_FROM	0x00000004U
#define STATMOUNT_MNT_ROOT		0x00000008U
#define STATMOUNT_MNT_POINT		0x00000010U
#define STATMOUNT_FS_TYPE		0x00000020U
#define STATMOUNT_MNT_NS_ID		0x00000040U
#define STATMOUNT_MNT_OPTS		0x00000080U
#define STATMOUNT_FS_SUBTYPE		0x00000100U
#define STATMOUNT_SB_SOURCE		0x00000200U
#define STATMOUNT_OPT_ARRAY		0x00000400U
#define STATMOUNT_OPT_SEC_ARRAY		0x00000800U
#endif
#ifndef STATMOUNT_SUPPORTED_MASK
#define STATMOUNT_SUPPORTED_MASK	0x00001000U
#endif
#ifndef STATMOUNT_MNT_UIDMAP
#define STATMOUNT_MNT_UIDMAP		0x00002000U
#define STATMOUNT_MNT_GIDMAP		0x00004000U
#endif
#ifndef STATMOUNT_BY_FD
#define STATMOUNT_BY_FD			0x00000001U
#endif
#ifndef MS_SUBMOUNT
#define MS_SUBMOUNT		(1<<26)
#endif
#ifndef MS_NOREMOTELOCK
#define MS_NOREMOTELOCK		(1<<27)
#endif
#ifndef MOUNT_ATTR_SIZE_VER0
#define MOUNT_ATTR_SIZE_VER0	32
#endif

#ifndef MNT_DETACH
#define MNT_DETACH		2
#endif
#ifndef MNT_EXPIRE
#define MNT_EXPIRE		4
#endif
#ifndef UMOUNT_NOFOLLOW
#define UMOUNT_NOFOLLOW		8
#endif

