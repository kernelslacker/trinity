#pragma once

/*
 * Wrapper around <linux/mount.h> that ships #ifndef-guarded fallbacks
 * for the new-mount-API constants (fsopen / fsconfig / fsmount) added
 * after our installed uapi header.  The syscalls themselves are
 * available on every kernel trinity targets (fsopen landed in 5.2);
 * only the symbolic constants may be missing on older build hosts.
 */
#include <linux/mount.h>

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
