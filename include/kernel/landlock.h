#ifndef TRINITY_KERNEL_LANDLOCK_H
#define TRINITY_KERNEL_LANDLOCK_H

/*
 * Wrapper around <linux/landlock.h> that ships #ifndef-guarded fallbacks
 * for the landlock_create_ruleset() flags and for LANDLOCK_ADD_RULE_QUIET,
 * the sys_landlock_add_rule() flag that suppresses per-rule audit records,
 * and, for ABI 12, the permission bits, the rule types and the layout of
 * the permission rules.  Older kernel-headers packages predate the names.
 */
#include <stddef.h>
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

#ifndef LANDLOCK_PERMISSION_NAMESPACE_USE
#define LANDLOCK_PERMISSION_NAMESPACE_USE	(1ULL << 0)
#endif
#ifndef LANDLOCK_PERMISSION_CAPABILITY_USE
#define LANDLOCK_PERMISSION_CAPABILITY_USE	(1ULL << 1)
#endif

/*
 * landlock_add_rule() rule types.  <linux/landlock.h> gains
 * LANDLOCK_RULE_NAMESPACE and LANDLOCK_RULE_CAPABILITY in ABI 12, and an
 * enum member is not a macro #ifndef can probe, so all four are spelt here.
 */
enum landlock_rule_type_compat {
	LANDLOCK_RULE_PATH_BENEATH_COMPAT = 1,
	LANDLOCK_RULE_NET_PORT_COMPAT,
	LANDLOCK_RULE_NAMESPACE_COMPAT,
	LANDLOCK_RULE_CAPABILITY_COMPAT,
};

/*
 * struct landlock_namespace_attr and struct landlock_capability_attr share
 * one layout: the permission the rule is for, the members it allows
 * (CLONE_NEW* flags, or 1ULL << CAP_*) and the members whose denial stays out
 * of the audit log.  Under a name of its own so a host header that has the
 * uapi pair cannot clash with it.
 */
struct landlock_permission_attr {
	__u64 permissions;
	__u64 allowed;
	__u64 quiet;
};
_Static_assert(sizeof(struct landlock_permission_attr) == 24,
	       "the permission rules are three u64s");

/*
 * struct landlock_ruleset_attr as ABI 12 has it: the access masks, the quiet
 * masks that must be subsets of them, and the permissions the ruleset
 * handles.  A host header stops at @scoped, or at @quiet_scoped, so the layout
 * is kept here under a name of its own.
 */
struct landlock_ruleset_attr_abi12 {
	__u64 handled_access_fs;
	__u64 handled_access_net;
	__u64 scoped;
	__u64 quiet_access_fs;
	__u64 quiet_access_net;
	__u64 quiet_scoped;
	__u64 handled_permissions;
};
_Static_assert(sizeof(struct landlock_ruleset_attr_abi12) == 56,
	       "the ABI 12 ruleset attr is seven u64s");
_Static_assert(offsetof(struct landlock_ruleset_attr_abi12,
			handled_permissions) == 48,
	       "handled_permissions moved");

#endif
