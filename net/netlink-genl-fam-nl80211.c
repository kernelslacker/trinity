/*
 * Genetlink family grammar: nl80211.
 *
 * nl80211 is the wireless configuration interface — wiphy, virtual
 * interfaces, scans, stations, mesh, regulatory, the lot.  It is one
 * of the largest genetlink families in the kernel (200+ commands,
 * 350+ attributes) and historically one of the buggiest networking
 * subsystems: 15+ public CVEs over the last few years, almost all
 * rooted in incorrect or missing per-attribute validation in deep
 * parser paths (nl80211_set_cqm_rssi, nl80211_set_station,
 * nl80211_join_ibss, etc.).
 *
 * Starter command set is the read-side dump path, which exercises
 * cfg80211_get_wiphy_dev, the per-interface policy tables, and the
 * scan/station object dumpers without needing CAP_NET_ADMIN.  Even
 * that subset reaches a meaningful slice of net/wireless/nl80211.c
 * that the random-id netlink fuzzer never touches.
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
 * commands plus a couple of nested containers (SCAN_FREQUENCIES,
 * SCAN_SSIDS) so the spec-driven nested emitter exercises the
 * scan-trigger validators when they fire on garbage payloads.
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
