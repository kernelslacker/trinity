#pragma once

/*
 * <linux/lsm.h> arrived in 6.8, so it is pulled in only where it exists;
 * the fallbacks cover the lsm_*_self_attr() vocabulary either way.
 */
#if __has_include(<linux/lsm.h>)
#include <linux/lsm.h>
#endif

#ifndef LSM_ATTR_CURRENT
#define LSM_ATTR_CURRENT	100
#define LSM_ATTR_EXEC		101
#define LSM_ATTR_FSCREATE	102
#define LSM_ATTR_KEYCREATE	103
#define LSM_ATTR_PREV		104
#define LSM_ATTR_SOCKCREATE	105
#endif

#ifndef LSM_FLAG_SINGLE
#define LSM_FLAG_SINGLE		0x0001
#endif

/* LSM IDs from linux/lsm.h; guard in case system headers provide them. */
#ifndef LSM_ID_CAPABILITY
#define LSM_ID_CAPABILITY	100
#endif
#ifndef LSM_ID_SELINUX
#define LSM_ID_SELINUX		101
#endif
#ifndef LSM_ID_SMACK
#define LSM_ID_SMACK		102
#endif
#ifndef LSM_ID_TOMOYO
#define LSM_ID_TOMOYO		103
#endif
#ifndef LSM_ID_APPARMOR
#define LSM_ID_APPARMOR		104
#endif
#ifndef LSM_ID_YAMA
#define LSM_ID_YAMA		105
#endif
#ifndef LSM_ID_LOADPIN
#define LSM_ID_LOADPIN		106
#endif
#ifndef LSM_ID_SAFESETID
#define LSM_ID_SAFESETID	107
#endif
#ifndef LSM_ID_LOCKDOWN
#define LSM_ID_LOCKDOWN		108
#endif
#ifndef LSM_ID_BPF
#define LSM_ID_BPF		109
#endif
#ifndef LSM_ID_LANDLOCK
#define LSM_ID_LANDLOCK		110
#endif
#ifndef LSM_ID_IMA
#define LSM_ID_IMA		111
#endif
#ifndef LSM_ID_EVM
#define LSM_ID_EVM		112
#endif
#ifndef LSM_ID_IPE
#define LSM_ID_IPE		113
#endif
