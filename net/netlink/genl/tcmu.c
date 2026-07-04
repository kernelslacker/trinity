/*
 * Genetlink family grammar: TCM-USER (target_core_user / TCMU).
 *
 * The TCMU subsystem (drivers/target/target_core_user.c) exposes its
 * userspace daemon-completion handshake through a single generic-netlink
 * family ("TCM-USER") with four user-callable commands, all .doit and
 * all GENL_ADMIN_PERM: TCMU_CMD_SET_FEATURES (toggles the
 * kern_cmd_reply_supported global from a single SUPP_KERN_CMD_REPLY u8),
 * and the three completion acks TCMU_CMD_ADDED_DEVICE_DONE /
 * TCMU_CMD_REMOVED_DEVICE_DONE / TCMU_CMD_RECONFIG_DEVICE_DONE that
 * userspace returns after acting on the matching device-state event.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "TCM-USER", so the per-cmd nla_policy walker plus the
 * three completion-ack dispatchers (tcmu_genl_cmd_done) have been
 * routinely cold under generic netlink fuzzing; resolving the family
 * at first NETLINK_GENERIC use lets the message generator address real
 * TCMU messages whose attribute shapes plausibly survive the per-cmd
 * policy.  The three completion acks then walk tcmu_nl_cmd_list under
 * tcmu_nl_cmd_mutex and reject with -ENODEV when no live TCMU device
 * matches the supplied DEVICE_ID -- but the parse surface (the policy
 * walker, the dev_id / cmd_status copy-out) is reached regardless.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample / ncsi
 * model, a single flat nla_attr_spec table lists every id the kernel's
 * tcmu_attr_policy gates on: DEVICE (NLA_STRING, the per-device name),
 * MINOR (u32, the uio minor selector), CMD_STATUS (NLA_S32 in the
 * kernel policy, listed here as a 4-byte u32 since wire-size is
 * identical and the spec generator has no signed kind), DEVICE_ID
 * (u32, the dev_index match key), and SUPP_KERN_CMD_REPLY (u8, the
 * SET_FEATURES capability toggle).  TCMU_ATTR_DEV_CFG / DEV_SIZE /
 * WRITECACHE / PAD exist in the uapi enum but are not in the kernel's
 * policy table -- omitted here to keep the generator's attribute
 * picker focused on ids the validator actually reads.
 *
 * The family declares .version = 2 on the kernel side and uses
 * GENL_DONT_VALIDATE_STRICT on every op, so a mismatched version byte
 * doesn't fast-reject; default_version still mirrors the declared
 * value so the message generator's wire format matches real
 * userspace traffic.  hdrsize stays 0: TCM-USER has no family-specific
 * fixed header, attributes follow the genlmsghdr directly.
 *
 * Header gating mirrors the team / hsr / fou / psample / ncsi families:
 * <linux/target_core_user.h> is the upstream UAPI header carrying every
 * TCMU_CMD_* / TCMU_ATTR_* enum referenced below.  Build hosts lacking
 * the header silently drop the family from the registry instead of
 * failing the build.  Per-symbol #ifndef shims in
 * include/kernel/target_core_user.h fill in any ids missing from a
 * stale uapi.
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
	.default_version = 2,
};

#endif /* __has_include(<linux/target_core_user.h>) */
