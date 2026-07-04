/*
 * Genetlink family grammar: legacy IEEE 802.15.4 MAC control plane
 * ("802.15.4 MAC"), distinct from the modern nl802154 family in
 * netlink-genl-fam-nl802154.c.  The two coexist in the kernel and
 * share no command or attribute namespace: nl802154 owns the modern
 * wpan_phy / scan / coordinator surface; this legacy family owns the
 * original IFACE add/del, ASSOCIATE / SCAN / START request path, MAC
 * tuning, and link-layer security key / device / level configuration.
 *
 * Target: the per-cmd nla_policy walker in
 * net/ieee802154/{nl-mac.c,nl-phy.c,nl_policy.c} plus the LLSEC_ *
 * add/del/list dispatch chains.  Random nlmsg_type ids essentially
 * never matched the runtime-assigned "802.15.4 MAC" family_id, so
 * these arms stayed cold; resolving the family once at first
 * NETLINK_GENERIC use lets the generator address real messages whose
 * attribute shapes plausibly survive the shared input-side policy.
 *
 * Flat attribute table over the global IEEE802154_ATTR_ * enum.
 * Encoding rules that matter for validate-time acceptance: signed
 * scalar attrs (TXPOWER, FRAME_RETRIES, CCA_ED_LEVEL) go on the wire
 * as their unsigned same-width counterparts (identical bytes; handler
 * reads through nla_get_s8 / nla_get_s32).  HW_ADDR and the extended
 * LLSEC key-source variants are declared NLA_HW_ADDR (aliased to
 * NLA_U64), so they emit as eight-byte U64.  Fixed-length binary
 * attrs (ED_LIST 27, CHANNEL_PAGE_LIST 128, LLSEC_KEY_BYTES 16,
 * LLSEC_KEY_USAGE_COMMANDS 32) use NLA_KIND_BINARY within the
 * kernel's .len bound.  IEEE802154_ATTR_SEC / _PAD have no policy
 * entry -- emitted as zero-length binary so the wire shape stays
 * well-formed.
 *
 * Header gating: include/linux/nl802154.h is kernel-internal (not
 * shipped via uapi).  include/kernel/ieee802154.h vendors every
 * referenced IEEE802154_CMD_ * / IEEE802154_ATTR_ * id as an #ifndef
 * shim mirroring the (ABI-stable since 2.6.32) kernel enum ordering.
 * The family registers unconditionally; runtime CTRL_CMD_GETFAMILY
 * decides whether CONFIG_IEEE802154 is on and the module loaded.
 */

#include "kernel/ieee802154.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar ieee802154_cmds[] = {
	{ IEEE802154_LIST_PHY,			"IEEE802154_LIST_PHY" },
	{ IEEE802154_ADD_IFACE,			"IEEE802154_ADD_IFACE" },
	{ IEEE802154_DEL_IFACE,			"IEEE802154_DEL_IFACE" },
	{ IEEE802154_ASSOCIATE_REQ,		"IEEE802154_ASSOCIATE_REQ" },
	{ IEEE802154_ASSOCIATE_RESP,		"IEEE802154_ASSOCIATE_RESP" },
	{ IEEE802154_DISASSOCIATE_REQ,		"IEEE802154_DISASSOCIATE_REQ" },
	{ IEEE802154_SCAN_REQ,			"IEEE802154_SCAN_REQ" },
	{ IEEE802154_START_REQ,			"IEEE802154_START_REQ" },
	{ IEEE802154_LIST_IFACE,		"IEEE802154_LIST_IFACE" },
	{ IEEE802154_SET_MACPARAMS,		"IEEE802154_SET_MACPARAMS" },
	{ IEEE802154_LLSEC_GETPARAMS,		"IEEE802154_LLSEC_GETPARAMS" },
	{ IEEE802154_LLSEC_SETPARAMS,		"IEEE802154_LLSEC_SETPARAMS" },
	{ IEEE802154_LLSEC_LIST_KEY,		"IEEE802154_LLSEC_LIST_KEY" },
	{ IEEE802154_LLSEC_ADD_KEY,		"IEEE802154_LLSEC_ADD_KEY" },
	{ IEEE802154_LLSEC_DEL_KEY,		"IEEE802154_LLSEC_DEL_KEY" },
	{ IEEE802154_LLSEC_LIST_DEV,		"IEEE802154_LLSEC_LIST_DEV" },
	{ IEEE802154_LLSEC_ADD_DEV,		"IEEE802154_LLSEC_ADD_DEV" },
	{ IEEE802154_LLSEC_DEL_DEV,		"IEEE802154_LLSEC_DEL_DEV" },
	{ IEEE802154_LLSEC_LIST_DEVKEY,		"IEEE802154_LLSEC_LIST_DEVKEY" },
	{ IEEE802154_LLSEC_ADD_DEVKEY,		"IEEE802154_LLSEC_ADD_DEVKEY" },
	{ IEEE802154_LLSEC_DEL_DEVKEY,		"IEEE802154_LLSEC_DEL_DEVKEY" },
	{ IEEE802154_LLSEC_LIST_SECLEVEL,	"IEEE802154_LLSEC_LIST_SECLEVEL" },
	{ IEEE802154_LLSEC_ADD_SECLEVEL,	"IEEE802154_LLSEC_ADD_SECLEVEL" },
	{ IEEE802154_LLSEC_DEL_SECLEVEL,	"IEEE802154_LLSEC_DEL_SECLEVEL" },
};

static const struct nla_attr_spec ieee802154_attrs[] = {
	/* DEV_NAME / PHY_NAME: NLA_STRING -- the kernel's policy uses
	 * .type = NLA_STRING with no explicit .len bound; the message
	 * generator caps the emitted payload via the standard string
	 * sizing path. */
	{ IEEE802154_ATTR_DEV_NAME,			NLA_KIND_STRING, 15 },
	{ IEEE802154_ATTR_DEV_INDEX,			NLA_KIND_U32,    4 },
	{ IEEE802154_ATTR_STATUS,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_SHORT_ADDR,			NLA_KIND_U16,    2 },
	/* HW_ADDR and the COORD/SRC/DEST hardware-address variants are
	 * NLA_HW_ADDR (aliased to NLA_U64) -- eight-byte EUI-64. */
	{ IEEE802154_ATTR_HW_ADDR,			NLA_KIND_U64,    8 },
	{ IEEE802154_ATTR_PAN_ID,			NLA_KIND_U16,    2 },
	{ IEEE802154_ATTR_CHANNEL,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_COORD_SHORT_ADDR,		NLA_KIND_U16,    2 },
	{ IEEE802154_ATTR_COORD_HW_ADDR,		NLA_KIND_U64,    8 },
	{ IEEE802154_ATTR_COORD_PAN_ID,			NLA_KIND_U16,    2 },
	{ IEEE802154_ATTR_SRC_SHORT_ADDR,		NLA_KIND_U16,    2 },
	{ IEEE802154_ATTR_SRC_HW_ADDR,			NLA_KIND_U64,    8 },
	{ IEEE802154_ATTR_SRC_PAN_ID,			NLA_KIND_U16,    2 },
	{ IEEE802154_ATTR_DEST_SHORT_ADDR,		NLA_KIND_U16,    2 },
	{ IEEE802154_ATTR_DEST_HW_ADDR,			NLA_KIND_U64,    8 },
	{ IEEE802154_ATTR_DEST_PAN_ID,			NLA_KIND_U16,    2 },
	{ IEEE802154_ATTR_CAPABILITY,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_REASON,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_SCAN_TYPE,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_CHANNELS,			NLA_KIND_U32,    4 },
	{ IEEE802154_ATTR_DURATION,			NLA_KIND_U8,     1 },
	/* ED_LIST is a 27-byte per-channel energy-detect list; the
	 * kernel policy uses .len = 27 (no .type), so any payload up
	 * to the bound is accepted. */
	{ IEEE802154_ATTR_ED_LIST,			NLA_KIND_BINARY, 27 },
	{ IEEE802154_ATTR_BCN_ORD,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_SF_ORD,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_PAN_COORD,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_BAT_EXT,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_COORD_REALIGN,		NLA_KIND_U8,     1 },
	/* SEC has no policy entry -- emit a zero-length binary blob so
	 * the wire shape is well-formed; the input-side walker
	 * silently ignores ids absent from the policy table. */
	{ IEEE802154_ATTR_SEC,				NLA_KIND_BINARY, 0 },
	{ IEEE802154_ATTR_PAGE,				NLA_KIND_U8,     1 },
	/* CHANNEL_PAGE_LIST: 32 pages * 4 bytes per page == 128. */
	{ IEEE802154_ATTR_CHANNEL_PAGE_LIST,		NLA_KIND_BINARY, 128 },
	{ IEEE802154_ATTR_PHY_NAME,			NLA_KIND_STRING, 15 },
	{ IEEE802154_ATTR_DEV_TYPE,			NLA_KIND_U8,     1 },
	/* TXPOWER and FRAME_RETRIES: kernel-side NLA_S8 -- same wire
	 * width as U8, signed interpretation happens in the handler. */
	{ IEEE802154_ATTR_TXPOWER,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_LBT_ENABLED,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_CCA_MODE,			NLA_KIND_U8,     1 },
	/* CCA_ED_LEVEL: kernel-side NLA_S32 -- same wire width as U32. */
	{ IEEE802154_ATTR_CCA_ED_LEVEL,			NLA_KIND_U32,    4 },
	{ IEEE802154_ATTR_CSMA_RETRIES,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_CSMA_MIN_BE,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_CSMA_MAX_BE,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_FRAME_RETRIES,		NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_LLSEC_ENABLED,		NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_LLSEC_SECLEVEL,		NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_LLSEC_KEY_MODE,		NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_LLSEC_KEY_SOURCE_SHORT,	NLA_KIND_U32,    4 },
	{ IEEE802154_ATTR_LLSEC_KEY_SOURCE_EXTENDED,	NLA_KIND_U64,    8 },
	{ IEEE802154_ATTR_LLSEC_KEY_ID,			NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_LLSEC_FRAME_COUNTER,		NLA_KIND_U32,    4 },
	/* LLSEC_KEY_BYTES: AES-128 key material, .len = 16 in policy. */
	{ IEEE802154_ATTR_LLSEC_KEY_BYTES,		NLA_KIND_BINARY, 16 },
	{ IEEE802154_ATTR_LLSEC_KEY_USAGE_FRAME_TYPES,	NLA_KIND_U8,     1 },
	/* LLSEC_KEY_USAGE_COMMANDS: 258-bit command-id bitmap rounded
	 * to bytes, .len = 258/8 == 32 in policy. */
	{ IEEE802154_ATTR_LLSEC_KEY_USAGE_COMMANDS,	NLA_KIND_BINARY, 32 },
	{ IEEE802154_ATTR_LLSEC_FRAME_TYPE,		NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_LLSEC_CMD_FRAME_ID,		NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_LLSEC_SECLEVELS,		NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_LLSEC_DEV_OVERRIDE,		NLA_KIND_U8,     1 },
	{ IEEE802154_ATTR_LLSEC_DEV_KEY_MODE,		NLA_KIND_U8,     1 },
};

struct genl_family_grammar fam_ieee802154 = {
	.name = IEEE802154_NL_NAME,
	.cmds = ieee802154_cmds,
	.n_cmds = ARRAY_SIZE(ieee802154_cmds),
	.attrs = ieee802154_attrs,
	.n_attrs = ARRAY_SIZE(ieee802154_attrs),
	.default_version = IEEE802154_FAMILY_VERSION,
};
