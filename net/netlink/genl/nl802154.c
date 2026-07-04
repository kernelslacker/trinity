/*
 * Genetlink family grammar: nl802154 (IEEE 802.15.4 / 6LoWPAN
 * control plane).
 *
 * Target: the per-cmd nla_policy walker in net/ieee802154/nl802154.c
 * plus the GET_WPAN_PHY / NEW_INTERFACE / TRIGGER_SCAN / ASSOCIATE /
 * SET_SEC_ * dispatch chains.  Random nlmsg_type ids essentially
 * never matched the runtime-assigned "nl802154" family_id, so these
 * arms stayed cold under generic netlink fuzzing.  Resolving the
 * family once at first NETLINK_GENERIC use lets the message generator
 * address real nl802154 commands whose attribute shapes plausibly
 * survive each per-cmd policy.  On a host without a wpan_phy the
 * dispatcher bails -ENODEV after the full attribute walk -- which is
 * the parser-level coverage this grammar exists to provide.
 *
 * Flat attribute table: nl802154_policy is itself flat
 * (NL802154_ATTR_MAX+1 slots), so the per-cmd walker validates each
 * child against one global shape.  Signed scalar attrs (TX_POWER,
 * CCA_ED_LEVEL, MAX_FRAME_RETRIES) are emitted as their unsigned
 * same-width counterparts -- wire format identical, kernel reads the
 * bytes through nla_get_s32 / nla_get_s8.  NLA_REJECT attrs
 * (SCAN_PREAMBLE_CODES, SCAN_MEAN_PRF) and reply-only attrs
 * (GENERATION, CHANNELS_SUPPORTED, PAD) are omitted -- both trip
 * -EINVAL before the handler runs.  GENL_ADMIN_PERM commands stay in:
 * the policy walker runs before the capability check, so unprivileged
 * traffic still exercises the validator.
 *
 * Header gating: include/net/nl802154.h is not shipped via uapi;
 * include/kernel/nl802154.h vendors every referenced NL802154_CMD_ *
 * / NL802154_ATTR_ * id as an #ifndef shim mirroring the (ABI-stable)
 * kernel enum ordering.  The family registers unconditionally and
 * runtime CTRL_CMD_GETFAMILY decides whether the running kernel
 * actually carries it.
 */

#include "kernel/nl802154.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar nl802154_cmds[] = {
	{ NL802154_CMD_GET_WPAN_PHY,		"NL802154_CMD_GET_WPAN_PHY" },
	{ NL802154_CMD_SET_WPAN_PHY,		"NL802154_CMD_SET_WPAN_PHY" },
	{ NL802154_CMD_GET_INTERFACE,		"NL802154_CMD_GET_INTERFACE" },
	{ NL802154_CMD_SET_INTERFACE,		"NL802154_CMD_SET_INTERFACE" },
	{ NL802154_CMD_NEW_INTERFACE,		"NL802154_CMD_NEW_INTERFACE" },
	{ NL802154_CMD_DEL_INTERFACE,		"NL802154_CMD_DEL_INTERFACE" },
	{ NL802154_CMD_SET_CHANNEL,		"NL802154_CMD_SET_CHANNEL" },
	{ NL802154_CMD_SET_PAN_ID,		"NL802154_CMD_SET_PAN_ID" },
	{ NL802154_CMD_SET_SHORT_ADDR,		"NL802154_CMD_SET_SHORT_ADDR" },
	{ NL802154_CMD_SET_TX_POWER,		"NL802154_CMD_SET_TX_POWER" },
	{ NL802154_CMD_SET_CCA_MODE,		"NL802154_CMD_SET_CCA_MODE" },
	{ NL802154_CMD_SET_CCA_ED_LEVEL,	"NL802154_CMD_SET_CCA_ED_LEVEL" },
	{ NL802154_CMD_SET_MAX_FRAME_RETRIES,	"NL802154_CMD_SET_MAX_FRAME_RETRIES" },
	{ NL802154_CMD_SET_BACKOFF_EXPONENT,	"NL802154_CMD_SET_BACKOFF_EXPONENT" },
	{ NL802154_CMD_SET_MAX_CSMA_BACKOFFS,	"NL802154_CMD_SET_MAX_CSMA_BACKOFFS" },
	{ NL802154_CMD_SET_LBT_MODE,		"NL802154_CMD_SET_LBT_MODE" },
	{ NL802154_CMD_SET_ACKREQ_DEFAULT,	"NL802154_CMD_SET_ACKREQ_DEFAULT" },
	{ NL802154_CMD_SET_WPAN_PHY_NETNS,	"NL802154_CMD_SET_WPAN_PHY_NETNS" },
	{ NL802154_CMD_TRIGGER_SCAN,		"NL802154_CMD_TRIGGER_SCAN" },
	{ NL802154_CMD_ABORT_SCAN,		"NL802154_CMD_ABORT_SCAN" },
	{ NL802154_CMD_SEND_BEACONS,		"NL802154_CMD_SEND_BEACONS" },
	{ NL802154_CMD_STOP_BEACONS,		"NL802154_CMD_STOP_BEACONS" },
	{ NL802154_CMD_ASSOCIATE,		"NL802154_CMD_ASSOCIATE" },
	{ NL802154_CMD_DISASSOCIATE,		"NL802154_CMD_DISASSOCIATE" },
	{ NL802154_CMD_SET_MAX_ASSOCIATIONS,	"NL802154_CMD_SET_MAX_ASSOCIATIONS" },
	{ NL802154_CMD_LIST_ASSOCIATIONS,	"NL802154_CMD_LIST_ASSOCIATIONS" },
	/* CONFIG_IEEE802154_NL802154_EXPERIMENTAL-gated link-layer
	 * security config surface; on kernels without the option the
	 * dispatcher returns -EOPNOTSUPP cleanly. */
	{ NL802154_CMD_SET_SEC_PARAMS,		"NL802154_CMD_SET_SEC_PARAMS" },
	{ NL802154_CMD_GET_SEC_KEY,		"NL802154_CMD_GET_SEC_KEY" },
	{ NL802154_CMD_NEW_SEC_KEY,		"NL802154_CMD_NEW_SEC_KEY" },
	{ NL802154_CMD_DEL_SEC_KEY,		"NL802154_CMD_DEL_SEC_KEY" },
	{ NL802154_CMD_GET_SEC_DEV,		"NL802154_CMD_GET_SEC_DEV" },
	{ NL802154_CMD_NEW_SEC_DEV,		"NL802154_CMD_NEW_SEC_DEV" },
	{ NL802154_CMD_DEL_SEC_DEV,		"NL802154_CMD_DEL_SEC_DEV" },
	{ NL802154_CMD_GET_SEC_DEVKEY,		"NL802154_CMD_GET_SEC_DEVKEY" },
	{ NL802154_CMD_NEW_SEC_DEVKEY,		"NL802154_CMD_NEW_SEC_DEVKEY" },
	{ NL802154_CMD_DEL_SEC_DEVKEY,		"NL802154_CMD_DEL_SEC_DEVKEY" },
	{ NL802154_CMD_GET_SEC_LEVEL,		"NL802154_CMD_GET_SEC_LEVEL" },
	{ NL802154_CMD_NEW_SEC_LEVEL,		"NL802154_CMD_NEW_SEC_LEVEL" },
	{ NL802154_CMD_DEL_SEC_LEVEL,		"NL802154_CMD_DEL_SEC_LEVEL" },
};

/*
 * Attribute spec follows nl802154_policy[] in
 * net/ieee802154/nl802154.c.  The kernel's policy table is flat over
 * the global enum nl802154_attrs, so this single flat table covers
 * every command's input-side validator without per-command
 * namespacing.  String lengths mirror the kernel's .len bounds:
 * IFNAMSIZ-1 == 15 for IFNAME, and the WPAN_PHY_NAME bound is
 * 20-1 == 19 (the upstream policy literally encodes "20-1").
 */
static const struct nla_attr_spec nl802154_attrs[] = {
	{ NL802154_ATTR_WPAN_PHY,		NLA_KIND_U32,    4 },
	{ NL802154_ATTR_WPAN_PHY_NAME,		NLA_KIND_STRING, 19 },
	{ NL802154_ATTR_IFINDEX,		NLA_KIND_U32,    4 },
	{ NL802154_ATTR_IFNAME,			NLA_KIND_STRING, 15 },
	{ NL802154_ATTR_IFTYPE,			NLA_KIND_U32,    4 },
	{ NL802154_ATTR_WPAN_DEV,		NLA_KIND_U64,    8 },
	{ NL802154_ATTR_PAGE,			NLA_KIND_U8,     1 },
	{ NL802154_ATTR_CHANNEL,		NLA_KIND_U8,     1 },
	{ NL802154_ATTR_PAN_ID,			NLA_KIND_U16,    2 },
	{ NL802154_ATTR_SHORT_ADDR,		NLA_KIND_U16,    2 },
	/* TX_POWER, CCA_ED_LEVEL: kernel-side NLA_S32 -- same wire
	 * width as U32, signed interpretation happens in the handler. */
	{ NL802154_ATTR_TX_POWER,		NLA_KIND_U32,    4 },
	{ NL802154_ATTR_CCA_MODE,		NLA_KIND_U32,    4 },
	{ NL802154_ATTR_CCA_OPT,		NLA_KIND_U32,    4 },
	{ NL802154_ATTR_CCA_ED_LEVEL,		NLA_KIND_U32,    4 },
	/* MAX_FRAME_RETRIES: kernel-side NLA_S8 -- same wire width as U8. */
	{ NL802154_ATTR_MAX_FRAME_RETRIES,	NLA_KIND_U8,     1 },
	{ NL802154_ATTR_MAX_BE,			NLA_KIND_U8,     1 },
	{ NL802154_ATTR_MIN_BE,			NLA_KIND_U8,     1 },
	{ NL802154_ATTR_MAX_CSMA_BACKOFFS,	NLA_KIND_U8,     1 },
	{ NL802154_ATTR_LBT_MODE,		NLA_KIND_U8,     1 },
	{ NL802154_ATTR_SUPPORTED_CHANNEL,	NLA_KIND_U32,    4 },
	{ NL802154_ATTR_EXTENDED_ADDR,		NLA_KIND_U64,    8 },
	{ NL802154_ATTR_WPAN_PHY_CAPS,		NLA_KIND_NESTED, 0 },
	{ NL802154_ATTR_SUPPORTED_COMMANDS,	NLA_KIND_NESTED, 0 },
	{ NL802154_ATTR_ACKREQ_DEFAULT,		NLA_KIND_U8,     1 },
	{ NL802154_ATTR_PID,			NLA_KIND_U32,    4 },
	{ NL802154_ATTR_NETNS_FD,		NLA_KIND_U32,    4 },
	{ NL802154_ATTR_COORDINATOR,		NLA_KIND_NESTED, 0 },
	{ NL802154_ATTR_SCAN_TYPE,		NLA_KIND_U8,     1 },
	{ NL802154_ATTR_SCAN_FLAGS,		NLA_KIND_U32,    4 },
	{ NL802154_ATTR_SCAN_CHANNELS,		NLA_KIND_U32,    4 },
	{ NL802154_ATTR_SCAN_DURATION,		NLA_KIND_U8,     1 },
	{ NL802154_ATTR_SCAN_DONE_REASON,	NLA_KIND_U8,     1 },
	{ NL802154_ATTR_BEACON_INTERVAL,	NLA_KIND_U8,     1 },
	{ NL802154_ATTR_MAX_ASSOCIATIONS,	NLA_KIND_U32,    4 },
	{ NL802154_ATTR_PEER,			NLA_KIND_NESTED, 0 },
	/* CONFIG_IEEE802154_NL802154_EXPERIMENTAL-gated link-layer
	 * security attrs; on kernels without the option the policy
	 * table caps out at NL802154_ATTR_PEER and these ids land
	 * above NL802154_ATTR_MAX, which the per-cmd validator
	 * rejects cleanly at the attribute walk. */
	{ NL802154_ATTR_SEC_ENABLED,		NLA_KIND_U8,     1 },
	{ NL802154_ATTR_SEC_OUT_LEVEL,		NLA_KIND_U32,    4 },
	{ NL802154_ATTR_SEC_OUT_KEY_ID,		NLA_KIND_NESTED, 0 },
	{ NL802154_ATTR_SEC_FRAME_COUNTER,	NLA_KIND_U32,    4 },
	{ NL802154_ATTR_SEC_LEVEL,		NLA_KIND_NESTED, 0 },
	{ NL802154_ATTR_SEC_DEVICE,		NLA_KIND_NESTED, 0 },
	{ NL802154_ATTR_SEC_DEVKEY,		NLA_KIND_NESTED, 0 },
	{ NL802154_ATTR_SEC_KEY,		NLA_KIND_NESTED, 0 },
};

struct genl_family_grammar fam_nl802154 = {
	.name = NL802154_GENL_NAME,
	.cmds = nl802154_cmds,
	.n_cmds = ARRAY_SIZE(nl802154_cmds),
	.attrs = nl802154_attrs,
	.n_attrs = ARRAY_SIZE(nl802154_attrs),
	.default_version = NL802154_FAMILY_VERSION,
};
