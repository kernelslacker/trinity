/*
 * Genetlink family grammar: nl802154 (IEEE 802.15.4 / 6LoWPAN
 * subsystem control plane).
 *
 * The nl802154 subsystem exposes wireless 802.15.4 PHY, MAC and
 * security configuration through a single generic-netlink family
 * ("nl802154") covering WPAN PHY enumeration, virtual interface
 * lifecycle, per-PHY channel / CCA / TX-power / CSMA / retry tuning,
 * scan and beacon control, association management, and (under
 * CONFIG_IEEE802154_NL802154_EXPERIMENTAL) the legacy link-layer
 * security parameter / key / device / level configuration surface.
 * Most commands require a wpan_phy / wpan_dev / netdev to bind to,
 * so on a host without an 802.15.4 PHY the dispatcher bails -ENODEV
 * after the full attribute walk completes -- which is the parser-
 * level coverage spec-driven fuzzing exists to provide.
 *
 * Random nlmsg_type ids essentially never matched the runtime-
 * assigned family_id for "nl802154", so the per-cmd nla_policy
 * walker in net/ieee802154/nl802154.c plus the GET_WPAN_PHY /
 * NEW_INTERFACE / TRIGGER_SCAN / ASSOCIATE / SET_SEC_* dispatch
 * chains have been routinely cold under generic netlink fuzzing;
 * resolving the family at first NETLINK_GENERIC use lets the
 * message generator address real nl802154 messages whose attribute
 * shapes plausibly survive each per-cmd policy.
 *
 * The user-callable command set covered here mirrors the entries of
 * enum nl802154_commands in include/net/nl802154.h that carry a
 * .doit or .dumpit handler in nl802154_ops[].  The four kernel-to-
 * userspace event ids (NEW_WPAN_PHY / DEL_WPAN_PHY emitted from the
 * core notifier chain, plus SCAN_EVENT / SCAN_DONE multicast events)
 * have no inbound handler and are omitted from cmds[].  Likewise the
 * "*_INTERFACE" SET / NEW / DEL trio is enumerated, but SET_INTERFACE
 * is unimplemented in this version of the kernel so the dispatcher
 * fast-rejects it via -EOPNOTSUPP -- listing it is harmless and a
 * future kernel may grow a handler for it.  Several commands carry
 * GENL_ADMIN_PERM, but the per-cmd nla_policy walker runs before the
 * capability check so unprivileged fuzz traffic still exercises the
 * validator.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psp / psample
 * model, a single flat nla_attr_spec table lists every id used by
 * any command in this family.  The nl802154 policy is itself flat
 * (nl802154_policy[NL802154_ATTR_MAX+1] in nl802154.c), so the
 * per-cmd policy walker validates each child against one global
 * shape -- there is no per-command namespace to enumerate.  Attrs
 * whose policy entry is NLA_REJECT (SCAN_PREAMBLE_CODES,
 * SCAN_MEAN_PRF) are omitted: the kernel returns -EINVAL on any
 * input containing them, so spending fuzz budget there is wasted
 * work that only flips -EINVAL on the validate side.  Reply-only
 * attrs (GENERATION, CHANNELS_SUPPORTED, PAD) are omitted on the
 * same grounds -- the policy table has no entry for them so the
 * input-side walker silently ignores them, and emitting one against
 * a kernel that does validate strictly trips -EINVAL without ever
 * reaching the handler.
 *
 * The signed scalar attrs (TX_POWER, CCA_ED_LEVEL declared NLA_S32;
 * MAX_FRAME_RETRIES declared NLA_S8) are emitted as their unsigned
 * same-width counterparts -- the wire format is identical, the
 * kernel's validator only checks the length, and the handler reads
 * the payload through nla_get_s32 / nla_get_s8 which interpret the
 * raw bytes as signed.  The U8-ranged attrs (PAGE, CHANNEL,
 * SCAN_TYPE, SCAN_DURATION, SCAN_DONE_REASON, BEACON_INTERVAL) are
 * emitted as plain U8: the kernel's range/max policies reject
 * out-of-band values at the validate step, which is exactly the
 * parser-level coverage we want.
 *
 * The family carries a nonzero declared version
 * (NL802154_FAMILY_VERSION = 1) so the default_version member is
 * initialised -- the kernel's dispatcher doesn't gate on the
 * genlmsghdr.version byte today, but matching the declared family
 * version keeps the message generator honest against any future
 * version-gated dispatch.  hdrsize stays 0: nl802154 has no
 * family-specific fixed header, attributes follow the genlmsghdr
 * directly.
 *
 * Header gating: the upstream kernel header is include/net/
 * nl802154.h, which the upstream comment explicitly flags as not
 * shipped via uapi ("currently we don't shipping this file via
 * uapi"), so no installed sysroot exposes these symbols by their
 * canonical names.  include/kernel/nl802154.h vendors every
 * referenced NL802154_CMD_* / NL802154_ATTR_* id as a hardcoded
 * #ifndef shim mirroring the kernel enum ordering; the upstream
 * "don't change the order or add anything between, this is ABI!"
 * comment keeps the wire ids stable.  No build-host gate is needed
 * because the shim is self-contained -- the family registers
 * unconditionally and runtime resolution against CTRL_CMD_GETFAMILY
 * decides whether the running kernel actually carries the family.
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
