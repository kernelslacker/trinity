/*
 * Genetlink family grammar: net-shaper, the 6.13+ per-netdev HW rate
 * limiting control plane (net/shaper/).  The inner HANDLE and CAPS
 * attribute namespaces are not listed; see the attribute table.
 */

/* Keeps the TU non-empty when the guard below drops the family. */
#include "arch.h"

#if __has_include(<linux/net_shaper.h>)

#include "kernel/net_shaper.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * net_shaper exposes five user-callable commands.  SET / DELETE /
 * GROUP are GENL_ADMIN_PERM, which the genl core checks before the
 * nla_policy walker runs; CAP_GET / GET are not.  Listing every id
 * exercises every per-cmd parser symmetrically for a child that
 * passes that check.
 */
static const struct genl_cmd_grammar net_shaper_cmds[] = {
	{ NET_SHAPER_CMD_CAP_GET,	"NET_SHAPER_CMD_CAP_GET" },
	{ NET_SHAPER_CMD_GET,		"NET_SHAPER_CMD_GET" },
	{ NET_SHAPER_CMD_SET,		"NET_SHAPER_CMD_SET" },
	{ NET_SHAPER_CMD_DELETE,	"NET_SHAPER_CMD_DELETE" },
	{ NET_SHAPER_CMD_GROUP,		"NET_SHAPER_CMD_GROUP" },
};

/*
 * Attribute spec follows the top-level NET_SHAPER_A_* enum in
 * <linux/net_shaper.h>.  IFINDEX is the u32 netdev selector that
 * every cmd keys on.  METRIC is a u32 enum (BPS / PPS).  BW_MIN /
 * BW_MAX / BURST are u64 rate/burst-size scalars; PRIORITY / WEIGHT
 * are u32 scheduling scalars.  HANDLE, PARENT, and LEAVES are the
 * three nominally nested attrs — emitted as empty containers
 * psample-TUNNEL / ovpn-PEER style so the kernel's nla_validate
 * accepts them at the outer level without recursing into the per-nest
 * sub-policies.  The inner NET_SHAPER_A_HANDLE_{SCOPE,ID} and
 * NET_SHAPER_A_CAPS_* enums share id 1..N with the top-level
 * namespace; the shim header carries #ifndef-guarded fallbacks for
 * those inner ids for the next reader who extends the grammar to
 * recursive nested emission.
 */
static const struct nla_attr_spec net_shaper_attrs[] = {
	{ NET_SHAPER_A_HANDLE,		NLA_KIND_NESTED, 0 },
	{ NET_SHAPER_A_METRIC,		NLA_KIND_U32,    4 },
	{ NET_SHAPER_A_BW_MIN,		NLA_KIND_U64,    8 },
	{ NET_SHAPER_A_BW_MAX,		NLA_KIND_U64,    8 },
	{ NET_SHAPER_A_BURST,		NLA_KIND_U64,    8 },
	{ NET_SHAPER_A_PRIORITY,	NLA_KIND_U32,    4 },
	{ NET_SHAPER_A_WEIGHT,		NLA_KIND_U32,    4 },
	{ NET_SHAPER_A_IFINDEX,		NLA_KIND_U32,    4 },
	{ NET_SHAPER_A_PARENT,		NLA_KIND_NESTED, 0 },
	{ NET_SHAPER_A_LEAVES,		NLA_KIND_NESTED, 0 },
};

struct genl_family_grammar fam_net_shaper = {
	.name = NET_SHAPER_FAMILY_NAME,
	.cmds = net_shaper_cmds,
	.n_cmds = ARRAY_SIZE(net_shaper_cmds),
	.attrs = net_shaper_attrs,
	.n_attrs = ARRAY_SIZE(net_shaper_attrs),
	.default_version = NET_SHAPER_FAMILY_VERSION,
};

#endif /* __has_include(<linux/net_shaper.h>) */
