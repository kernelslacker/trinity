#pragma once

#include <linux/seccomp.h>

#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW		0x7fff0000U
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF		0x7fc00000U
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER		1
#endif
#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER		2
#endif
