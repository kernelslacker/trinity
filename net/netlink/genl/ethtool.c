/*
 * Genetlink family grammar: ethtool, targeting net/ethtool/netlink.c and
 * the per-command files beside it.  Only the read-side commands are listed;
 * WOL_GET and MODULE_EEPROM_GET are GENL_UNS_ADMIN_PERM, the rest carry no
 * flag.  Each is keyed on the nested *_HEADER attribute that names the
 * net_device, and takes the table of its own policy.
 */

#if __has_include(<linux/ethtool_netlink_generated.h>)

#include <linux/ethtool.h>
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
 * The nests of STRSET_GET's STRINGSETS, which strset_parse_request() walks
 * as a nest of STRINGSET nests holding an ID each, and of TSINFO_GET's
 * HWTSTAMP_PROVIDER, from ethnl_ts_hwtst_prov_policy.
 */
static const struct nla_attr_spec ethtool_stringset_attrs[] = {
	{ ETHTOOL_A_STRINGSET_ID,	NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec ethtool_stringsets_attrs[] = {
	{ ETHTOOL_A_STRINGSETS_STRINGSET, NLA_KIND_NESTED, 0, 0,
	  ethtool_stringset_attrs, ARRAY_SIZE(ethtool_stringset_attrs) },
};

static const struct nla_attr_spec ethtool_ts_provider_attrs[] = {
	{ ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX,		NLA_KIND_U32, 4 },
	{ ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER,	NLA_KIND_U32, 4 },
};

/*
 * The ops validate strictly against an ethnl_*_get_policy of their own that
 * ends at its own last id, so a request meets only the ids of its cmd's.
 * Most of those policies are the HEADER alone, and every *_HEADER is
 * attribute 1 but STATS_GET's, which follows a PAD, so one table stands for
 * them; the cmds that nest the stats or the PHY-aware header have tables
 * of theirs.  The stats sources go up to ETHTOOL_MAC_STATS_SRC_PMAC and the
 * EEPROM offset and length stay within a page pair and a page; the I2C
 * address, an NLA_U8 range, is plain, and STATS_GET's GROUPS, a bitset
 * nest, is left out.
 */
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

static const struct nla_attr_spec ethtool_pause_get_attrs[] = {
	{ ETHTOOL_A_PAUSE_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_stats_attrs, ARRAY_SIZE(ethtool_header_stats_attrs) },
	{ ETHTOOL_A_PAUSE_STATS_SRC,	NLA_KIND_U32_RANGE,
	  ETHTOOL_MAC_STATS_SRC_PMAC, 0 },
};

static const struct nla_attr_spec ethtool_tsinfo_get_attrs[] = {
	{ ETHTOOL_A_TSINFO_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_stats_attrs, ARRAY_SIZE(ethtool_header_stats_attrs) },
	{ ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER, NLA_KIND_NESTED, 0, 0,
	  ethtool_ts_provider_attrs, ARRAY_SIZE(ethtool_ts_provider_attrs) },
};

static const struct nla_attr_spec ethtool_module_eeprom_get_attrs[] = {
	{ ETHTOOL_A_MODULE_EEPROM_HEADER, NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs) },
	{ ETHTOOL_A_MODULE_EEPROM_OFFSET, NLA_KIND_U32_RANGE, 255, 0 },
	{ ETHTOOL_A_MODULE_EEPROM_LENGTH, NLA_KIND_U32_RANGE, 128, 1 },
	{ ETHTOOL_A_MODULE_EEPROM_PAGE,	NLA_KIND_U8,     1 },
	{ ETHTOOL_A_MODULE_EEPROM_BANK,	NLA_KIND_U8,     1 },
	{ ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS, NLA_KIND_U8, 1 },
};

static const struct nla_attr_spec ethtool_stats_get_attrs[] = {
	{ ETHTOOL_A_STATS_HEADER,	NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs) },
	{ ETHTOOL_A_STATS_SRC,		NLA_KIND_U32_RANGE,
	  ETHTOOL_MAC_STATS_SRC_PMAC, 0 },
};

static const struct nla_attr_spec ethtool_rss_get_attrs[] = {
	{ ETHTOOL_A_RSS_HEADER,		NLA_KIND_NESTED, 0, 0,
	  ethtool_header_attrs, ARRAY_SIZE(ethtool_header_attrs) },
	{ ETHTOOL_A_RSS_CONTEXT,	NLA_KIND_U32,    4 },
	{ ETHTOOL_A_RSS_START_CONTEXT,	NLA_KIND_U32,    4 },
};

static const struct genl_cmd_grammar ethtool_cmds[] = {
	{ ETHTOOL_MSG_STRSET_GET,        "ETHTOOL_MSG_STRSET_GET",
	  ethtool_strset_get_attrs, ARRAY_SIZE(ethtool_strset_get_attrs) },
	{ ETHTOOL_MSG_LINKINFO_GET,      "ETHTOOL_MSG_LINKINFO_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_LINKMODES_GET,     "ETHTOOL_MSG_LINKMODES_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_LINKSTATE_GET,     "ETHTOOL_MSG_LINKSTATE_GET",
	  ethtool_get_stats_attrs, ARRAY_SIZE(ethtool_get_stats_attrs) },
	{ ETHTOOL_MSG_DEBUG_GET,         "ETHTOOL_MSG_DEBUG_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_WOL_GET,           "ETHTOOL_MSG_WOL_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
	{ ETHTOOL_MSG_FEATURES_GET,      "ETHTOOL_MSG_FEATURES_GET",
	  ethtool_get_attrs, ARRAY_SIZE(ethtool_get_attrs) },
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
};

struct genl_family_grammar fam_ethtool = {
	.name = ETHTOOL_GENL_NAME,
	.cmds = ethtool_cmds,
	.n_cmds = ARRAY_SIZE(ethtool_cmds),
	.default_version = ETHTOOL_GENL_VERSION,
};

#endif /* __has_include(<linux/ethtool_netlink_generated.h>) */
