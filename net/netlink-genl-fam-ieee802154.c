/*
 * Genetlink family grammar: legacy IEEE 802.15.4 MAC control plane.
 *
 * This is the legacy ieee802154 generic-netlink family registered by
 * net/ieee802154/netlink.c under the kernel family name "802.15.4 MAC"
 * -- distinct from the modern nl802154 family (kernel family name
 * "nl802154") vendored in net/netlink-genl-fam-nl802154.c.  Both
 * families coexist in the kernel: nl802154 owns the modern wpan_phy /
 * wpan_dev / scan / coordinator control surface, while the legacy
 * family below owns the original IFACE add/del, ASSOCIATE / SCAN /
 * START request path, MAC parameter tuning, and the link-layer
 * security key / device / level configuration surface dispatched out
 * of nl-mac.c / nl-phy.c.  The two share no command or attribute
 * namespace.
 *
 * Random nlmsg_type ids essentially never matched the runtime-assigned
 * family_id for "802.15.4 MAC", so the per-cmd nla_policy walker in
 * net/ieee802154/{nl-mac.c,nl-phy.c,nl_policy.c} plus the LLSEC_*
 * add/del/list dispatch chains have been routinely cold under generic
 * netlink fuzzing; resolving the family at first NETLINK_GENERIC use
 * lets the message generator address real legacy-ieee802154 messages
 * whose attribute shapes plausibly survive the shared input-side
 * policy.
 *
 * The user-callable command set covered here mirrors the entries of
 * ieee802154_ops[] in net/ieee802154/netlink.c (the genl_small_ops
 * dispatch table).  The *_CONF / *_INDIC / event-only command ids
 * (ASSOCIATE_CONF, DISASSOCIATE_INDIC, BEACON_NOTIFY_INDIC, ...) have
 * no inbound handler and are omitted from cmds[]; likewise the GTS_*
 * / RX_ENABLE_* / SET_REQ / GET_REQ / RESET_REQ / SYNC_REQ / POLL_REQ
 * ids reserve numeric slots in the enum but are unimplemented in this
 * version of the kernel and the dispatcher fast-rejects them via
 * -EOPNOTSUPP.  Listing only the dispatched ops keeps fuzz budget on
 * the parsers that actually run.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psp / psample /
 * nl802154 model, a single flat nla_attr_spec table lists every id
 * used by any command in this family.  The legacy ieee802154 policy
 * (ieee802154_policy[] in net/ieee802154/nl_policy.c) is itself flat
 * over the global IEEE802154_ATTR_* enum, so the per-cmd policy
 * walker validates each child against one shared shape -- there is no
 * per-command namespace to enumerate.  The signed scalar attrs
 * (TXPOWER and FRAME_RETRIES declared NLA_S8; CCA_ED_LEVEL declared
 * NLA_S32) are emitted as their unsigned same-width counterparts --
 * the wire format is identical, the kernel's validator only checks
 * the length, and the handler reads the payload through nla_get_s8 /
 * nla_get_s32 which interpret the raw bytes as signed.  HW_ADDR and
 * the COORD_/SRC_/DEST_/LLSEC_KEY_SOURCE_EXTENDED variants are
 * declared NLA_HW_ADDR which the policy header aliases to NLA_U64;
 * they are listed below as NLA_KIND_U64 to match the eight-byte wire
 * width the kernel's nla_validate gate expects.  The fixed-length
 * binary attrs (ED_LIST 27 bytes, CHANNEL_PAGE_LIST 32*4 == 128
 * bytes, LLSEC_KEY_BYTES 16, LLSEC_KEY_USAGE_COMMANDS 258/8 == 32)
 * use NLA_KIND_BINARY with the kernel's .len bound -- the legacy
 * policy uses .len rather than .type so any payload up to the bound
 * is accepted, matching the spec walker's behaviour on this family.
 * IEEE802154_ATTR_SEC and IEEE802154_ATTR_PAD have no policy entry
 * (the input-side walker silently ignores them); they are emitted as
 * a zero-length binary payload so the wire shape is well-formed
 * without forcing a particular content.
 *
 * The family carries a nonzero declared version (the kernel registers
 * .version = 1) so the default_version member is initialised -- the
 * kernel's dispatcher doesn't gate on the genlmsghdr.version byte
 * today, but matching the declared family version keeps the message
 * generator honest against any future version-gated dispatch.
 * hdrsize stays 0: the legacy family registers .hdrsize = 0 (no
 * family-specific fixed header), attributes follow the genlmsghdr
 * directly.
 *
 * Header gating: the kernel-side enum lives in
 * include/linux/nl802154.h which is a kernel-internal header and is
 * NOT installed via uapi, so the installed sysroot has no header that
 * names the IEEE802154_* symbols.  include/kernel/ieee802154.h
 * vendors every referenced IEEE802154_CMD_* / IEEE802154_ATTR_* id as
 * a hardcoded #ifndef shim mirroring the kernel enum ordering, which
 * has been ABI-stable since the original 2.6.32 ieee802154 socket
 * support.  No build-host gate is needed because the shim is
 * self-contained -- the family registers unconditionally and runtime
 * resolution against CTRL_CMD_GETFAMILY decides whether the running
 * kernel actually carries the family (CONFIG_IEEE802154 must be on
 * and the ieee802154 module loaded for the controller to return a
 * family_id).
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
