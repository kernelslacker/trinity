/*
 * Genetlink family grammar: ethtool.
 *
 * The ethtool-netlink interface (introduced in 5.6) replaced the
 * legacy SIOCETHTOOL ioctl with a generic netlink family.  It carries
 * 60+ command pairs (each a *_GET / *_SET / *_NTF triple) and a
 * per-message attr namespace stitched together by a shared HEADER
 * sub-attr (ETHTOOL_A_HEADER_DEV_INDEX / DEV_NAME) that drives the
 * net_device lookup before per-message validation runs.
 *
 * Starter command set targets the read-side dump path for the
 * configuration objects most commonly poked by userspace tooling:
 * link state, ring buffers, channels, coalesce, and feature bits.
 * These all dispatch through ethnl_default_doit() / ethnl_default_dump()
 * after the shared header parser, so the same grammar lights up
 * net/ethtool/{linkinfo,linkstate,rings,channels,coalesce,features}.c
 * in one shot.
 *
 * Caveat: ETHTOOL_A_*_HEADER is a NESTED outer carrying children from
 * a separate shared namespace (ETHTOOL_A_HEADER_DEV_INDEX = 1, etc.).
 * The single-table spec emitter doesn't model per-attr child policies,
 * so the nested children we generate for the HEADER outer are picked
 * from this table by their numeric position; positions 1-4 happen to
 * overlap with the kernel-side header child policy so a meaningful
 * fraction of generated nested payloads survive the inner validator
 * and reach the per-cmd handler with a usable net_device pointer.
 */

#if __has_include(<linux/ethtool_netlink_generated.h>)

#include <linux/ethtool_netlink_generated.h>

#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar ethtool_cmds[] = {
	{ ETHTOOL_MSG_LINKINFO_GET,  "ETHTOOL_MSG_LINKINFO_GET" },
	{ ETHTOOL_MSG_LINKMODES_GET, "ETHTOOL_MSG_LINKMODES_GET" },
	{ ETHTOOL_MSG_LINKSTATE_GET, "ETHTOOL_MSG_LINKSTATE_GET" },
	{ ETHTOOL_MSG_RINGS_GET,     "ETHTOOL_MSG_RINGS_GET" },
	{ ETHTOOL_MSG_CHANNELS_GET,  "ETHTOOL_MSG_CHANNELS_GET" },
	{ ETHTOOL_MSG_COALESCE_GET,  "ETHTOOL_MSG_COALESCE_GET" },
	{ ETHTOOL_MSG_FEATURES_GET,  "ETHTOOL_MSG_FEATURES_GET" },
	{ ETHTOOL_MSG_TSINFO_GET,    "ETHTOOL_MSG_TSINFO_GET" },
};

/*
 * Attribute spec table.  Position 1 is always *_HEADER for every
 * starter command (ETHTOOL_A_RINGS_HEADER = ETHTOOL_A_LINKINFO_HEADER
 * = ... = 1) so a single NESTED entry at type 1 covers them all.
 * Positions 2-4 are intentionally seeded with values that match the
 * shared ETHTOOL_A_HEADER_* child namespace so nested-child generation
 * has a chance of producing valid header contents:
 *   1: HEADER outer (NESTED) / HEADER_DEV_INDEX child (U32)
 *   2: per-cmd MAX/RX_MAX (U32) / HEADER_DEV_NAME child (NUL_STRING)
 *   3: per-cmd RX_MINI_MAX (U32) / HEADER_FLAGS child (U32)
 *   4: per-cmd RX_JUMBO_MAX (U32) / HEADER_PHY_INDEX child (U32)
 */
static const struct nla_attr_spec ethtool_attrs[] = {
	{ ETHTOOL_A_RINGS_HEADER,        NLA_KIND_NESTED, 0 },
	{ ETHTOOL_A_HEADER_DEV_NAME,     NLA_KIND_STRING, 16 },
	{ ETHTOOL_A_HEADER_FLAGS,        NLA_KIND_U32,    4 },
	{ ETHTOOL_A_HEADER_PHY_INDEX,    NLA_KIND_U32,    4 },
	/* A handful of per-cmd numeric attrs that are common across the
	 * starter command set; the kernel's per-cmd policy gate accepts
	 * U32-shaped attrs at most positions and lets the message reach
	 * the deeper handler. */
	{ ETHTOOL_A_RINGS_RX,            NLA_KIND_U32,    4 },
	{ ETHTOOL_A_RINGS_TX,            NLA_KIND_U32,    4 },
	{ ETHTOOL_A_CHANNELS_RX_COUNT,   NLA_KIND_U32,    4 },
	{ ETHTOOL_A_CHANNELS_TX_COUNT,   NLA_KIND_U32,    4 },
	{ ETHTOOL_A_LINKMODES_AUTONEG,   NLA_KIND_U8,     1 },
	{ ETHTOOL_A_LINKMODES_SPEED,     NLA_KIND_U32,    4 },
	{ ETHTOOL_A_LINKMODES_DUPLEX,    NLA_KIND_U8,     1 },
};

struct genl_family_grammar fam_ethtool = {
	.name = ETHTOOL_GENL_NAME,
	.cmds = ethtool_cmds,
	.n_cmds = ARRAY_SIZE(ethtool_cmds),
	.attrs = ethtool_attrs,
	.n_attrs = ARRAY_SIZE(ethtool_attrs),
	.default_version = ETHTOOL_GENL_VERSION,
};

#endif /* __has_include(<linux/ethtool_netlink_generated.h>) */
