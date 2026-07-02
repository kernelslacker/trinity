#ifndef TRINITY_KERNEL_LANDLOCK_H
#define TRINITY_KERNEL_LANDLOCK_H

/*
 * Wrapper around <linux/landlock.h> that ships an #ifndef-guarded fallback
 * for LANDLOCK_ADD_RULE_QUIET, the sys_landlock_add_rule() flag added in
 * 6.15 that suppresses per-rule audit records.  Older kernel-headers
 * packages predate the name; the upstream uapi value is fixed at (1U << 0).
 */
#include <linux/landlock.h>

#ifndef LANDLOCK_ADD_RULE_QUIET
#define LANDLOCK_ADD_RULE_QUIET		(1U << 0)
#endif

#endif
