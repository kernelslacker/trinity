/*
 * Genetlink family grammar: ethtool, targeting net/ethtool/netlink.c and
 * the per-command files beside it.  The read-side commands are listed, and
 * the SET/ACT commands as they are added; WOL_GET and MODULE_EEPROM_GET
 * are GENL_UNS_ADMIN_PERM, the rest of the read side carries no flag, and
 * every SET/ACT command carries GENL_UNS_ADMIN_PERM.  Each is keyed on
 * the nested *_HEADER attribute that names the net_device, and takes the
 * table of its own policy.
 */

#if __has_include(<linux/ethtool_netlink_generated.h>)

#include <limits.h>
#include "kernel/ethtool.h"
#include "kernel/ethtool_netlink_generated.h"

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * The request header, from ethnl_header_policy, ethnl_header_policy_stats
 * for the cmds that can report statistics, and ethnl_header_policy_phy.
 * Every request nests one and the kernel validates it with the request, so
 * a FLAGS outside the policy's mask (ETHTOOL_FLAGS_BASIC, 0x3, or
 * ETHTOOL_FLAGS_STATS, 0x7) or a PHY_INDEX of 0 refuses the whole request.
 * DEV_NAME is an NLA_NUL_STRING of at most 127 bytes, and
 * ethnl_parse_header_dev_get() answers -ENODEV to one that names no device
 * or another than DEV_INDEX does, so it is "lo", which every netns has,
 * and DEV_INDEX is lo's, LOOPBACK_IFINDEX.
 */
static const struct nla_attr_spec ethtool_header_attrs[] = {
	{ ETHTOOL_A_HEADER_DEV_INDEX,	NLA_KIND_U32_RANGE, 1, 1 },
	{ ETHTOOL_A_HEADER_DEV_NAME,	NLA_KIND_STRING_WORD, 0, 0,
	  .word = "lo" },
	{ ETHTOOL_A_HEADER_FLAGS,	NLA_KIND_U32_MASK, 0x3 },
};

static const struct nla_attr_spec ethtool_header_stats_attrs[] = {
	{ ETHTOOL_A_HEADER_DEV_INDEX,	NLA_KIND_U32_RANGE, 1, 1 },
	{ ETHTOOL_A_HEADER_DEV_NAME,	NLA_KIND_STRING_WORD, 0, 0,
	  .word = "lo" },
	{ ETHTOOL_A_HEADER_FLAGS,	NLA_KIND_U32_MASK, 0x7 },
};

static const struct nla_attr_spec ethtool_header_phy_attrs[] = {
	{ ETHTOOL_A_HEADER_DEV_INDEX,	NLA_KIND_U32_RANGE, 1, 1 },
	{ ETHTOOL_A_HEADER_DEV_NAME,	NLA_KIND_STRING_WORD, 0, 0,
	  .word = "lo" },
	{ ETHTOOL_A_HEADER_FLAGS,	NLA_KIND_U32_MASK, 0x3 },
	{ ETHTOOL_A_HEADER_PHY_INDEX,	NLA_KIND_U32_RANGE, UINT32_MAX, 1 },
};

/*
 * The highest string set id: strset_parse_request() answers one from
 * ETH_SS_COUNT up -EOPNOTSUPP.  A header without ETH_SS_PHY_INTERFACES, the
 * newest set, counts ETH_SS_COUNT one short of it.
 */
#define ETHTOOL_SS_LAST	(ETH_SS_COUNT > ETH_SS_PHY_INTERFACES ? \
			 ETH_SS_COUNT - 1 : ETH_SS_PHY_INTERFACES)

/*
 * The nests of STRSET_GET's STRINGSETS, which strset_parse_request() walks
 * as a nest of STRINGSET nests holding an ID each, and of TSINFO_GET's
 * HWTSTAMP_PROVIDER, from ethnl_ts_hwtst_prov_policy.  The ID is a plain
 * NLA_U32 that the handler bounds, so it is a range to the last string set.
 */
static const struct nla_attr_spec ethtool_stringset_attrs[] = {
	{ ETHTOOL_A_STRINGSET_ID,	NLA_KIND_U32_RANGE, ETHTOOL_SS_LAST, 0 },
};

static const struct nla_attr_spec ethtool_stringsets_attrs[] = {
	{ ETHTOOL_A_STRINGSETS_STRINGSET, NLA_KIND_NESTED, 0, 0,
	  ethtool_stringset_attrs, ARRAY_SIZE(ethtool_stringset_attrs) },
};

/*
 * The provider's INDEX is a range from 0 to INT_MAX, since phc_index is an
 * int and -1 means no PHC, and its QUALIFIER is at most
 * HWTSTAMP_PROVIDER_QUALIFIER_CNT - 1, which is 1.
 */
static const struct nla_attr_spec ethtool_ts_provider_attrs[] = {
	{ ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX,		NLA_KIND_U32_RANGE, INT_MAX, 0 },
	{ ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER,	NLA_KIND_U32_RANGE, 1, 0 },
};

/* ETHNL_MAX_BITSET_SIZE lives in the kernel-internal net/ethtool/bitset.h,
 * not a uapi header; the value is the kernel's. */
#ifndef ETHNL_MAX_BITSET_SIZE
#define ETHNL_MAX_BITSET_SIZE	32767
#endif

/*
 * The bitset nest the SET handlers parse with ethnl_parse_bitset(), from
 * bitset_policy and bit_policy in net/ethtool/bitset.c.  The policy's
 * BITS is a bare NLA_NESTED whose children ethnl_parse_bitset() walks
 * with nla_for_each_nested and parses each as a bit nest, so it is an
 * array of bit nests here.  SIZE is capped at ETHNL_MAX_BITSET_SIZE.
 * The compact form's coupling, that VALUE and MASK are each
 * DIV_ROUND_UP(SIZE, 32) words long, is between two attributes and no
 * spec kind expresses it; the blobs are capped at 64 bytes, which holds
 * every in-tree bitset these handlers parse.  A NAME is a NUL string
 * the handler looks up in the bit names of the set being written.
 */
static const struct nla_attr_spec ethtool_bit_attrs[] = {
	{ ETHTOOL_A_BITSET_BIT_INDEX,	NLA_KIND_U32,    4 },
	{ ETHTOOL_A_BITSET_BIT_NAME,	NLA_KIND_STRING, 32 },
	{ ETHTOOL_A_BITSET_BIT_VALUE,	NLA_KIND_FLAG,   0 },
};

static const struct nla_attr_spec ethtool_bitset_attrs[] = {
	{ ETHTOOL_A_BITSET_NOMASK,	NLA_KIND_FLAG,		0 },
	{ ETHTOOL_A_BITSET_SIZE,	NLA_KIND_U32_RANGE,
	  ETHNL_MAX_BITSET_SIZE, 0 },
	{ ETHTOOL_A_BITSET_BITS,	NLA_KIND_NESTED_ARRAY, 0, 0,
	  ethtool_bit_attrs, ARRAY_SIZE(ethtool_bit_attrs) },
	{ ETHTOOL_A_BITSET_VALUE,	NLA_KIND_BINARY,	64, 0 },
	{ ETHTOOL_A_BITSET_MASK,	NLA_KIND_BINARY,	64, 0 },
};

/*
 * The ops validate strictly against an ethnl_*_get_policy of their own that
 * ends at its own last id, so a request meets only the ids of its cmd's.
 * Most of those policies are the HEADER alone, and every *_HEADER is
 * attribute 1 but STATS_GET's, which follows a PAD, so one table stands for
 * them; the cmds that nest the stats or the PHY-aware header have tables
 * of theirs.  The stats sources go up to ETHTOOL_MAC_STATS_SRC_PMAC and the
 * EEPROM offset and length stay within a page pair and a page; the I2C
 * address is an NLA_U8 range to ETH_MODULE_MAX_I2C_ADDRESS, and
 * STATS_GET's GROUPS, a bitset nest, is left out.
 */

/* ETH_MODULE_MAX_I2C_ADDRESS lives in the kernel-internal <linux/ethtool.h>,
 * not the uapi header, so a build host never defines it; the value is the
 * kernel's. */
#ifndef ETH_MODULE_MAX_I2C_ADDRESS
#define ETH_MODULE_MAX_I2C_ADDRESS	0x7f
#endif

static const struct nla_attr_spec ethtool_get_attrs[] = {
	{ ETHTOOL_A_LINKINFO_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs) },
};

static const struct nla_attr_spec ethtool_get_stats_attrs[] = {
	{ ETHTOOL_A_LINKSTATE_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_stats_attrs, ARRAY_SIZE(ethtool_header_stats_attrs) },
};

static const struct nla_attr_spec ethtool_get_phy_attrs[] = {
	{ ETHTOOL_A_PSE_HEADER,		NLA_KIND_NESTED, 0, 0,
	  ethtool_header_phy_attrs, ARRAY_SIZE(ethtool_header_phy_attrs) },
};

static const struct nla_attr_spec ethtool_strset_get_attrs[] = {
	{ ETHTOOL_A_STRSET_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_phy_attrs, ARRAY_SIZE(ethtool_header_phy_attrs) },
	{ ETHTOOL_A_STRSET_STRINGSETS,	NLA_KIND_NESTED, 0, 0,
	  ethtool_stringsets_attrs, ARRAY_SIZE(ethtool_stringsets_attrs) },
	{ ETHTOOL_A_STRSET_COUNTS_ONLY,	NLA_KIND_FLAG,   0 },
};

/*
 * Every doit but STRSET_GET's answers -EINVAL to a request without its
 * header, so a table of more than the header marks it, and
 * eeprom_parse_request() does the same without OFFSET, LENGTH, PAGE or
 * I2C_ADDRESS.
 */
static const struct nla_attr_spec ethtool_pause_get_attrs[] = {
	{ ETHTOOL_A_PAUSE_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_stats_attrs, ARRAY_SIZE(ethtool_header_stats_attrs),
	  .required = true },
	{ ETHTOOL_A_PAUSE_STATS_SRC,	NLA_KIND_U32_RANGE,
	  ETHTOOL_MAC_STATS_SRC_PMAC, 0 },
};

static const struct nla_attr_spec ethtool_tsinfo_get_attrs[] = {
	{ ETHTOOL_A_TSINFO_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_stats_attrs, ARRAY_SIZE(ethtool_header_stats_attrs),
	  .required = true },
	{ ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER, NLA_KIND_NESTED, 0, 0,
	  ethtool_ts_provider_attrs, ARRAY_SIZE(ethtool_ts_provider_attrs) },
};

static const struct nla_attr_spec ethtool_module_eeprom_get_attrs[] = {
	{ ETHTOOL_A_MODULE_EEPROM_HEADER, NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs),
	  .required = true },
	{ ETHTOOL_A_MODULE_EEPROM_OFFSET, NLA_KIND_U32_RANGE, 255, 0,
	  .required = true },
	{ ETHTOOL_A_MODULE_EEPROM_LENGTH, NLA_KIND_U32_RANGE, 128, 1,
	  .required = true },
	{ ETHTOOL_A_MODULE_EEPROM_PAGE,	NLA_KIND_U8,     1, .required = true },
	{ ETHTOOL_A_MODULE_EEPROM_BANK,	NLA_KIND_U8,     1 },
	{ ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS, NLA_KIND_U8_RANGE,
	  ETH_MODULE_MAX_I2C_ADDRESS, 0, .required = true },
};

static const struct nla_attr_spec ethtool_stats_get_attrs[] = {
	{ ETHTOOL_A_STATS_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs),
	  .required = true },
	{ ETHTOOL_A_STATS_SRC,		NLA_KIND_U32_RANGE,
	  ETHTOOL_MAC_STATS_SRC_PMAC, 0 },
};

static const struct nla_attr_spec ethtool_rss_get_attrs[] = {
	{ ETHTOOL_A_RSS_HEADER,		NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs),
	  .required = true },
	{ ETHTOOL_A_RSS_CONTEXT,	NLA_KIND_U32,    4 },
	{ ETHTOOL_A_RSS_START_CONTEXT,	NLA_KIND_U32,    4 },
};

/*
 * PORT_GET, from ethnl_port_get_policy: the header and a PORT_ID of at
 * least 1.  The doit answers -EINVAL without either, the header in
 * ethnl_parse_header_dev_get() and the id in port_parse_request(), but
 * ethnl_port_dump_start() answers a dump that carries a PORT_ID -EINVAL, so
 * the dump takes the header alone, which ethtool_get_attrs is.
 */
static const struct nla_attr_spec ethtool_port_get_attrs[] = {
	{ ETHTOOL_A_PORT_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs),
	  .required = true },
	{ ETHTOOL_A_PORT_ID,		NLA_KIND_U32_RANGE, UINT32_MAX, 1,
	  .required = true },
};

/*
 * LINKINFO_SET, from ethnl_linkinfo_set_policy: the header and three
 * plain U8s that ethnl_set_linkinfo assigns un-narrowed, so no bound.
 * The header is required, by GENL_REQ_ATTR_CHECK in
 * ethnl_default_set_doit.
 */
static const struct nla_attr_spec ethtool_linkinfo_set_attrs[] = {
	{ ETHTOOL_A_LINKINFO_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs),
	  .required = true },
	{ ETHTOOL_A_LINKINFO_PORT,		NLA_KIND_U8,     1 },
	{ ETHTOOL_A_LINKINFO_PHYADDR,		NLA_KIND_U8,     1 },
	{ ETHTOOL_A_LINKINFO_TP_MDIX_CTRL,	NLA_KIND_U8,     1 },
};

/*
 * LINKMODES_SET, from ethnl_linkmodes_set_policy: the header, the
 * autoneg/duplex/master-slave U8s that ethnl_set_linkmodes assigns
 * un-narrowed, SPEED as a plain U32, the OURS bitset, and LANES in
 * [1, 8] from NLA_POLICY_RANGE.
 */
static const struct nla_attr_spec ethtool_linkmodes_set_attrs[] = {
	{ ETHTOOL_A_LINKMODES_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs),
	  .required = true },
	{ ETHTOOL_A_LINKMODES_AUTONEG,	NLA_KIND_U8,     1 },
	{ ETHTOOL_A_LINKMODES_OURS,	NLA_KIND_NESTED, 0, 0,
	  ethtool_bitset_attrs, ARRAY_SIZE(ethtool_bitset_attrs) },
	{ ETHTOOL_A_LINKMODES_SPEED,	NLA_KIND_U32,    4 },
	{ ETHTOOL_A_LINKMODES_DUPLEX,	NLA_KIND_U8,     1 },
	{ ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG, NLA_KIND_U8, 1 },
	{ ETHTOOL_A_LINKMODES_LANES,	NLA_KIND_U32_RANGE, 8, 1 },
};

/*
 * DEBUG_SET, from ethnl_debug_set_policy: the header and the MSGMASK
 * bitset, which ethnl_set_debug parses with ethnl_parse_bitset().
 */
static const struct nla_attr_spec ethtool_debug_set_attrs[] = {
	{ ETHTOOL_A_DEBUG_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs),
	  .required = true },
	{ ETHTOOL_A_DEBUG_MSGMASK,	NLA_KIND_NESTED, 0, 0,
	  ethtool_bitset_attrs, ARRAY_SIZE(ethtool_bitset_attrs) },
};

/*
 * WOL_SET, from ethnl_wol_set_policy: the header, the MODES bitset,
 * and SOPASS, an NLA_BINARY of at most SOPASS_MAX bytes that
 * ethnl_set_wol copies into wol.sopass.
 */
static const struct nla_attr_spec ethtool_wol_set_attrs[] = {
	{ ETHTOOL_A_WOL_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs),
	  .required = true },
	{ ETHTOOL_A_WOL_MODES,		NLA_KIND_NESTED, 0, 0,
	  ethtool_bitset_attrs, ARRAY_SIZE(ethtool_bitset_attrs) },
	{ ETHTOOL_A_WOL_SOPASS,		NLA_KIND_BINARY, SOPASS_MAX, 0 },
};

/*
 * FEATURES_SET, from ethnl_features_set_policy: the header and the
 * WANTED bitset.  Both are required: ethnl_set_features answers
 * -EINVAL without WANTED, and parses the header with require_dev.
 */
static const struct nla_attr_spec ethtool_features_set_attrs[] = {
	{ ETHTOOL_A_FEATURES_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs),
	  .required = true },
	{ ETHTOOL_A_FEATURES_WANTED,	NLA_KIND_NESTED, 0, 0,
	  ethtool_bitset_attrs, ARRAY_SIZE(ethtool_bitset_attrs),
	  .required = true },
};

static const struct genl_cmd_grammar ethtool_cmds[] = {
	{ ETHTOOL_MSG_STRSET_GET,        "ETHTOOL_MSG_STRSET_GET",
	  ethtool_strset_get_attrs, ARRAY_SIZE(ethtool_strset_get_attrs) },
	{ ETHTOOL_MSG_LINKINFO_GET,      "ETHTOOL_MSG_LINKINFO_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_LINKINFO_SET,      "ETHTOOL_MSG_LINKINFO_SET",
	  ethtool_linkinfo_set_attrs, ARRAY_SIZE(ethtool_linkinfo_set_attrs) },
	{ ETHTOOL_MSG_LINKMODES_GET,     "ETHTOOL_MSG_LINKMODES_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_LINKMODES_SET,     "ETHTOOL_MSG_LINKMODES_SET",
	  ethtool_linkmodes_set_attrs, ARRAY_SIZE(ethtool_linkmodes_set_attrs) },
	{ ETHTOOL_MSG_LINKSTATE_GET,     "ETHTOOL_MSG_LINKSTATE_GET",
	  ethtool_get_stats_attrs, ARRAY_SIZE(ethtool_get_stats_attrs) },
	{ ETHTOOL_MSG_DEBUG_GET,         "ETHTOOL_MSG_DEBUG_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_DEBUG_SET,         "ETHTOOL_MSG_DEBUG_SET",
	  ethtool_debug_set_attrs, ARRAY_SIZE(ethtool_debug_set_attrs) },
	{ ETHTOOL_MSG_WOL_GET,           "ETHTOOL_MSG_WOL_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_WOL_SET,           "ETHTOOL_MSG_WOL_SET",
	  ethtool_wol_set_attrs, ARRAY_SIZE(ethtool_wol_set_attrs) },
	{ ETHTOOL_MSG_FEATURES_GET,      "ETHTOOL_MSG_FEATURES_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_FEATURES_SET,      "ETHTOOL_MSG_FEATURES_SET",
	  ethtool_features_set_attrs, ARRAY_SIZE(ethtool_features_set_attrs) },
	{ ETHTOOL_MSG_PRIVFLAGS_GET,     "ETHTOOL_MSG_PRIVFLAGS_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_RINGS_GET,         "ETHTOOL_MSG_RINGS_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_CHANNELS_GET,      "ETHTOOL_MSG_CHANNELS_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_COALESCE_GET,      "ETHTOOL_MSG_COALESCE_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_PAUSE_GET,         "ETHTOOL_MSG_PAUSE_GET",
	  ethtool_pause_get_attrs, ARRAY_SIZE(ethtool_pause_get_attrs) },
	{ ETHTOOL_MSG_EEE_GET,           "ETHTOOL_MSG_EEE_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_TSINFO_GET,        "ETHTOOL_MSG_TSINFO_GET",
	  ethtool_tsinfo_get_attrs, ARRAY_SIZE(ethtool_tsinfo_get_attrs) },
	{ ETHTOOL_MSG_TUNNEL_INFO_GET,   "ETHTOOL_MSG_TUNNEL_INFO_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_FEC_GET,           "ETHTOOL_MSG_FEC_GET",
	  ethtool_get_stats_attrs, ARRAY_SIZE(ethtool_get_stats_attrs) },
	{ ETHTOOL_MSG_MODULE_EEPROM_GET, "ETHTOOL_MSG_MODULE_EEPROM_GET",
	  ethtool_module_eeprom_get_attrs,
	  ARRAY_SIZE(ethtool_module_eeprom_get_attrs) },
	{ ETHTOOL_MSG_STATS_GET,         "ETHTOOL_MSG_STATS_GET",
	  ethtool_stats_get_attrs, ARRAY_SIZE(ethtool_stats_get_attrs) },
	{ ETHTOOL_MSG_PHC_VCLOCKS_GET,   "ETHTOOL_MSG_PHC_VCLOCKS_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_MODULE_GET,        "ETHTOOL_MSG_MODULE_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_PSE_GET,           "ETHTOOL_MSG_PSE_GET",
	  ethtool_get_phy_attrs, ARRAY_SIZE(ethtool_get_phy_attrs) },
	{ ETHTOOL_MSG_RSS_GET,           "ETHTOOL_MSG_RSS_GET",
	  ethtool_rss_get_attrs, ARRAY_SIZE(ethtool_rss_get_attrs) },
	{ ETHTOOL_MSG_PLCA_GET_CFG,      "ETHTOOL_MSG_PLCA_GET_CFG",
	  ethtool_get_phy_attrs, ARRAY_SIZE(ethtool_get_phy_attrs) },
	{ ETHTOOL_MSG_PLCA_GET_STATUS,   "ETHTOOL_MSG_PLCA_GET_STATUS",
	  ethtool_get_phy_attrs, ARRAY_SIZE(ethtool_get_phy_attrs) },
	{ ETHTOOL_MSG_MM_GET,            "ETHTOOL_MSG_MM_GET",
	  ethtool_get_stats_attrs, ARRAY_SIZE(ethtool_get_stats_attrs) },
	{ ETHTOOL_MSG_PHY_GET,           "ETHTOOL_MSG_PHY_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_TSCONFIG_GET,      "ETHTOOL_MSG_TSCONFIG_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_MSE_GET,           "ETHTOOL_MSG_MSE_GET",
	  ethtool_get_phy_attrs, ARRAY_SIZE(ethtool_get_phy_attrs) },
	{ ETHTOOL_MSG_PORT_GET,          "ETHTOOL_MSG_PORT_GET",
	  ethtool_port_get_attrs, ARRAY_SIZE(ethtool_port_get_attrs),
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
};

struct genl_family_grammar fam_ethtool = {
	.name = ETHTOOL_GENL_NAME,
	.cmds = ethtool_cmds,
	.n_cmds = ARRAY_SIZE(ethtool_cmds),
	.default_version = ETHTOOL_GENL_VERSION,
};

#endif /* __has_include(<linux/ethtool_netlink_generated.h>) */
