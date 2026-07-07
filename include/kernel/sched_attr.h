#pragma once

/*
 * Wrapper around <linux/sched/types.h> that ships #ifndef-guarded
 * fallbacks for sched_attr-related UAPI constants (the VER0/VER1
 * sized-ABI floors and the SCHED_FLAG_* bits) that may be missing
 * from older installed uapi headers.  The struct sched_attr type
 * itself comes from <linux/sched/types.h>.
 */
#include <linux/sched/types.h>

#include "kernel/sched.h"
#ifndef SCHED_ATTR_SIZE_VER0
#define SCHED_ATTR_SIZE_VER0 48
#endif
#ifndef SCHED_ATTR_SIZE_VER1
#define SCHED_ATTR_SIZE_VER1 56
#endif

/*
 * SCHED_FLAG_* fallbacks for build environments whose <linux/sched.h>
 * pre-dates the upstream flag definitions.  The kernel's own bit
 * positions are stable ABI, so the constants are safe to inline.
 */
#ifndef SCHED_FLAG_RESET_ON_FORK
#define SCHED_FLAG_RESET_ON_FORK	0x01
#endif
#ifndef SCHED_FLAG_RECLAIM
#define SCHED_FLAG_RECLAIM		0x02
#endif
#ifndef SCHED_FLAG_UTIL_CLAMP_MIN
#define SCHED_FLAG_UTIL_CLAMP_MIN	0x20
#endif
#ifndef SCHED_FLAG_UTIL_CLAMP_MAX
#define SCHED_FLAG_UTIL_CLAMP_MAX	0x40
#endif
