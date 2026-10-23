/*
 * Genetlink family grammar: nl80211 (cfg80211 wireless configuration),
 * targeting nl80211_policy and the read-side ops in net/wireless/nl80211.c.
 * Only the GET commands are listed; GET_KEY alone is GENL_UNS_ADMIN_PERM.
 */

#include <linux/nl80211.h>

#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar nl80211_cmds[] = {
	{ NL80211_CMD_GET_WIPHY,     "NL80211_CMD_GET_WIPHY" },
	{ NL80211_CMD_GET_INTERFACE, "NL80211_CMD_GET_INTERFACE" },
	{ NL80211_CMD_GET_STATION,   "NL80211_CMD_GET_STATION" },
	{ NL80211_CMD_GET_SCAN,      "NL80211_CMD_GET_SCAN" },
	{ NL80211_CMD_GET_REG,       "NL80211_CMD_GET_REG" },
	{ NL80211_CMD_GET_KEY,       "NL80211_CMD_GET_KEY" },
};

/*
 * Attribute spec table: identifying selectors for the read-side
 * commands plus two nested containers (SCAN_FREQUENCIES, SCAN_SSIDS),
 * bare NLA_NESTED in nl80211_policy that only the scan triggers walk
 * and the commands listed here never reach.
 *
 * Sizes follow nl80211_policy in net/wireless/nl80211.c:
 *   IFNAME      NUL_STRING, len IFNAMSIZ-1 (15)
 *   MAC         EXACT_LEN ETH_ALEN (6)
 *   KEY_IDX     U8, max 7
 *   REG_ALPHA2  BINARY, 2..3
 *   SSID        BINARY, up to IEEE80211_MAX_SSID_LEN (32)
 *   WIPHY_NAME  NUL_STRING, no .len => 64 is plenty
 */
static const struct nla_attr_spec nl80211_attrs[] = {
	{ NL80211_ATTR_WIPHY,             NLA_KIND_U32,    4 },
	{ NL80211_ATTR_WIPHY_NAME,        NLA_KIND_STRING, 64 },
	{ NL80211_ATTR_WIPHY_FREQ,        NLA_KIND_U32,    4 },
	{ NL80211_ATTR_IFINDEX,           NLA_KIND_U32,    4 },
	{ NL80211_ATTR_IFNAME,            NLA_KIND_STRING, 15 },
	{ NL80211_ATTR_IFTYPE,            NLA_KIND_U32,    4 },
	{ NL80211_ATTR_MAC,               NLA_KIND_BINARY, 6 },
	{ NL80211_ATTR_KEY_IDX,           NLA_KIND_U8,     1 },
	{ NL80211_ATTR_KEY_TYPE,          NLA_KIND_U32,    4 },
	{ NL80211_ATTR_REG_ALPHA2,        NLA_KIND_BINARY, 3 },
	{ NL80211_ATTR_SSID,              NLA_KIND_BINARY, 32 },
	{ NL80211_ATTR_SCAN_FREQUENCIES,  NLA_KIND_NESTED, 0 },
	{ NL80211_ATTR_SCAN_SSIDS,        NLA_KIND_NESTED, 0 },
	{ NL80211_ATTR_GENERATION,        NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_nl80211 = {
	.name = NL80211_GENL_NAME,
	.cmds = nl80211_cmds,
	.n_cmds = ARRAY_SIZE(nl80211_cmds),
	.attrs = nl80211_attrs,
	.n_attrs = ARRAY_SIZE(nl80211_attrs),
	.default_version = 1,
};
