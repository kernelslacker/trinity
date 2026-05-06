/*
 * Genetlink family grammar: TIPC (Transparent Inter-Process Communication).
 *
 * TIPC's userspace control plane uses its own generic-netlink family
 * "TIPCv2" for everything outside the socket API: bearer enable/disable,
 * cluster network configuration, link state, name table inspection, the
 * monitor framework, the UDP-tunnel media config, and the more recent
 * AEAD key rotation path (TIPC_NL_KEY_SET / TIPC_NL_KEY_FLUSH).  The
 * per-cmd nla_policy tables in net/tipc/bearer.c, net/tipc/link.c,
 * net/tipc/net.c, and net/tipc/node.c are the kind of hand-rolled
 * validators that have produced the bulk of the tipc CVE history
 * (CVE-2022-0382 tipc_msg_validate, CVE-2022-0435 tipc_link_proto_rcv
 * stack overflow, the tipc_nametbl double-free family) and benefit
 * from spec-driven fuzzing of valid family_id + plausible attr nests.
 *
 * Starter command set covers bearer + net + link + name-table, which
 * are the four nests that show up in essentially every TIPC bring-up
 * and teardown sequence.  TIPC_NL_KEY_SET / TIPC_NL_KEY_FLUSH are
 * included so the AEAD key rotation path (added in 5.10) gets touched
 * even though the parser-level coverage is narrower than the bearer
 * side.
 *
 * Header gating mirrors the mptcp_pm family: <linux/tipc_netlink.h>
 * carries the TIPC_GENL_V2_NAME constant plus every TIPC_NL_* and
 * TIPC_NLA_* enum we reference.  Distros without TIPC headers (or
 * cross-build sysroots stripped to a network-app-only subset) silently
 * drop the family from the registry instead of failing the build.
 */

#if __has_include(<linux/tipc_netlink.h>)

#include <linux/tipc_netlink.h>

#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar tipc_cmds[] = {
	{ TIPC_NL_BEARER_ENABLE,	"TIPC_NL_BEARER_ENABLE" },
	{ TIPC_NL_BEARER_DISABLE,	"TIPC_NL_BEARER_DISABLE" },
	{ TIPC_NL_BEARER_GET,		"TIPC_NL_BEARER_GET" },
	{ TIPC_NL_BEARER_SET,		"TIPC_NL_BEARER_SET" },
	{ TIPC_NL_NET_GET,		"TIPC_NL_NET_GET" },
	{ TIPC_NL_NET_SET,		"TIPC_NL_NET_SET" },
	{ TIPC_NL_LINK_GET,		"TIPC_NL_LINK_GET" },
	{ TIPC_NL_LINK_SET,		"TIPC_NL_LINK_SET" },
	{ TIPC_NL_LINK_RESET_STATS,	"TIPC_NL_LINK_RESET_STATS" },
	{ TIPC_NL_NAME_TABLE_GET,	"TIPC_NL_NAME_TABLE_GET" },
	{ TIPC_NL_PUBL_GET,		"TIPC_NL_PUBL_GET" },
	{ TIPC_NL_SOCK_GET,		"TIPC_NL_SOCK_GET" },
	{ TIPC_NL_MEDIA_GET,		"TIPC_NL_MEDIA_GET" },
	{ TIPC_NL_MON_GET,		"TIPC_NL_MON_GET" },
	{ TIPC_NL_MON_SET,		"TIPC_NL_MON_SET" },
};

/*
 * Attribute spec follows the per-nest enums in tipc_netlink.h.  The
 * outer namespace (TIPC_NLA_BEARER / TIPC_NLA_NET / TIPC_NLA_LINK /
 * TIPC_NLA_NAME_TABLE / TIPC_NLA_MEDIA / TIPC_NLA_MON / TIPC_NLA_SOCK)
 * is all NESTED — TIPC's controller dispatches per-cmd to a different
 * inner policy on each.  The inner attrs we list below are positioned
 * by numeric value within the same flat array; this is the same shape
 * mptcp_pm uses, and lets the single-table spec emitter produce nested
 * payloads whose tag values match whichever nest the cmd's policy is
 * walking.  The most common inner attributes (NAME strings, ID/ADDR
 * u32, BEARER UDP_OPTS / DOMAIN, NET_NODEID) are present so the bulk
 * of bearer/net/link bring-up payloads survive the inner validator.
 */
static const struct nla_attr_spec tipc_attrs[] = {
	{ TIPC_NLA_BEARER,		NLA_KIND_NESTED, 0 },
	{ TIPC_NLA_NET,			NLA_KIND_NESTED, 0 },
	{ TIPC_NLA_LINK,		NLA_KIND_NESTED, 0 },
	{ TIPC_NLA_NAME_TABLE,		NLA_KIND_NESTED, 0 },
	{ TIPC_NLA_MEDIA,		NLA_KIND_NESTED, 0 },
	{ TIPC_NLA_MON,			NLA_KIND_NESTED, 0 },
	{ TIPC_NLA_SOCK,		NLA_KIND_NESTED, 0 },
	{ TIPC_NLA_NODE,		NLA_KIND_NESTED, 0 },
	{ TIPC_NLA_PUBL,		NLA_KIND_NESTED, 0 },

	{ TIPC_NLA_BEARER_NAME,		NLA_KIND_STRING, 0 },
	{ TIPC_NLA_BEARER_DOMAIN,	NLA_KIND_U32,    4 },
	{ TIPC_NLA_BEARER_PROP,		NLA_KIND_NESTED, 0 },
	{ TIPC_NLA_BEARER_UDP_OPTS,	NLA_KIND_NESTED, 0 },

	{ TIPC_NLA_NET_ID,		NLA_KIND_U32,    4 },
	{ TIPC_NLA_NET_ADDR,		NLA_KIND_U32,    4 },
	{ TIPC_NLA_NET_NODEID,		NLA_KIND_U64,    8 },
	{ TIPC_NLA_NET_NODEID_W1,	NLA_KIND_U64,    8 },

	{ TIPC_NLA_LINK_NAME,		NLA_KIND_STRING, 0 },
	{ TIPC_NLA_LINK_PROP,		NLA_KIND_NESTED, 0 },
};

struct genl_family_grammar fam_tipc = {
	.name = TIPC_GENL_V2_NAME,
	.cmds = tipc_cmds,
	.n_cmds = ARRAY_SIZE(tipc_cmds),
	.attrs = tipc_attrs,
	.n_attrs = ARRAY_SIZE(tipc_attrs),
	.default_version = TIPC_GENL_V2_VERSION,
};

#endif /* __has_include(<linux/tipc_netlink.h>) */
