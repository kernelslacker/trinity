#ifndef TRINITY_KERNEL_LANDLOCK_H
#define TRINITY_KERNEL_LANDLOCK_H

/*
 * Wrapper around <linux/landlock.h> that ships #ifndef-guarded fallbacks
 * for the landlock_create_ruleset() flags and for LANDLOCK_ADD_RULE_QUIET,
 * the sys_landlock_add_rule() flag that suppresses per-rule audit records.
 * Older kernel-headers packages predate the names.
 */
#include <linux/landlock.h>

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION		(1U << 0)
#endif
#ifndef LANDLOCK_CREATE_RULESET_ERRATA
#define LANDLOCK_CREATE_RULESET_ERRATA		(1U << 1)
#endif

#ifndef LANDLOCK_ADD_RULE_QUIET
#define LANDLOCK_ADD_RULE_QUIET		(1U << 0)
#endif

#endif
