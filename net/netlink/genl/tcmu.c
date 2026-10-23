/*
 * Genetlink family grammar: TCM-USER (target_core_user / TCMU), targeting
 * tcmu_attr_policy and the completion-ack handlers in
 * drivers/target/target_core_user.c.  All four ops are GENL_ADMIN_PERM.
 */

#if __has_include(<linux/target_core_user.h>)

#include "kernel/target_core_user.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar tcmu_cmds[] = {
	{ TCMU_CMD_SET_FEATURES,	   "TCMU_CMD_SET_FEATURES" },
	{ TCMU_CMD_ADDED_DEVICE_DONE,	   "TCMU_CMD_ADDED_DEVICE_DONE" },
	{ TCMU_CMD_REMOVED_DEVICE_DONE,	   "TCMU_CMD_REMOVED_DEVICE_DONE" },
	{ TCMU_CMD_RECONFIG_DEVICE_DONE,   "TCMU_CMD_RECONFIG_DEVICE_DONE" },
};

/*
 * Attribute spec mirrors tcmu_attr_policy in target_core_user.c.
 * DEVICE is NLA_STRING (per-device name string, capped at 64 here --
 * the kernel doesn't bound it in the policy, but the netconfig name
 * is short in practice).  MINOR / DEVICE_ID are u32 selectors.
 * CMD_STATUS is NLA_S32 in the kernel; wire-size 4 matches u32 so the
 * spec generator emits it as u32 -- the validator's length check
 * passes and the cmd_done handler's nla_get_s32() recovers the sign.
 * SUPP_KERN_CMD_REPLY is the u8 SET_FEATURES capability toggle.
 * DEV_CFG / DEV_SIZE / WRITECACHE / PAD are in the uapi enum and emitted
 * by the kernel but not in tcmu_attr_policy, so they have no entry.
 */
static const struct nla_attr_spec tcmu_attrs[] = {
	{ TCMU_ATTR_DEVICE,		NLA_KIND_STRING, 64 },
	{ TCMU_ATTR_MINOR,		NLA_KIND_U32,    4 },
	{ TCMU_ATTR_CMD_STATUS,		NLA_KIND_U32,    4 },
	{ TCMU_ATTR_DEVICE_ID,		NLA_KIND_U32,    4 },
	{ TCMU_ATTR_SUPP_KERN_CMD_REPLY, NLA_KIND_U8,    1 },
};

struct genl_family_grammar fam_tcmu = {
	.name = "TCM-USER",
	.cmds = tcmu_cmds,
	.n_cmds = ARRAY_SIZE(tcmu_cmds),
	.attrs = tcmu_attrs,
	.n_attrs = ARRAY_SIZE(tcmu_attrs),
	/* The kernel's family .version; there is no uapi macro for it. */
	.default_version = 2,
};

#endif /* __has_include(<linux/target_core_user.h>) */
