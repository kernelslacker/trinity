/*
 * Genetlink family grammar: batadv (B.A.T.M.A.N. Advanced mesh routing).
 *
 * The batman-adv module exposes its userspace control plane through a
 * single generic-netlink family ("batadv") covering mesh / hardif /
 * vlan attribute query+set, originator / neighbour / gateway / TT /
 * BLA / DAT / multicast table dumps, the throughput-meter session
 * pair (TP_METER + TP_METER_CANCEL), and a routing-algo enumeration.
 * None of the user-facing commands carry GENL_ADMIN_PERM, so the
 * per-cmd nla_policy walker and the SET_MESH / SET_HARDIF / SET_VLAN
 * write paths in net/batman-adv/netlink.c run unprivileged — penetrating
 * the family demuxer with a real family_id puts every parser, the per-
 * mesh getter dispatcher, and the SET_* setter chains directly in the
 * fuzzer's reach.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "batadv", so the per-cmd policy walker plus the per-mesh
 * getter dispatch and the SET_* setter chains have been routinely cold
 * under generic netlink fuzzing; resolving the family at first
 * NETLINK_GENERIC use lets the message generator address real batadv
 * messages whose attribute shapes plausibly survive the per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample model,
 * a single flat nla_attr_spec table lists every id used by this
 * family's commands.  batadv uses a single flat BATADV_ATTR_* namespace
 * (no nested containers): the rich attribute set covers the mesh /
 * hardif / vlan IFINDEX+IFNAME+ADDRESS triples, the TT / BLA / DAT /
 * multicast table rows, the gateway / neighbour / originator metadata,
 * the throughput-meter result triple (RESULT/TEST_TIME/BYTES/COOKIE),
 * the per-mesh tunables propagated by SET_MESH (aggregated OGMs, AP
 * isolation, bonding, BLA, DAT, fragmentation, gateway bandwidth +
 * mode + selection class, hop penalty, log level, multicast force-
 * flood + fanout, network coding, OGM + ELP intervals, throughput
 * override), and a handful of presence-only flags (ACTIVE, FLAG_BEST,
 * BLA_OWN).
 *
 * Header gating mirrors the team / hsr / fou / psample families:
 * <linux/batman_adv.h> is the upstream UAPI header carrying every
 * BATADV_CMD_* and BATADV_ATTR_* enum referenced below.  Build hosts
 * lacking the header silently drop the family from the registry
 * instead of failing the build.  Per-symbol #ifndef shims fill in
 * newer BATADV_ATTR_* / BATADV_CMD_* on build hosts whose stale uapi
 * predates the per-mesh tunable additions, the VLAN GET/SET pair, or
 * the MULTICAST_FORCEFLOOD / MULTICAST_FANOUT attrs.
 */

#if __has_include(<linux/batman_adv.h>)

#include "kernel/batadv.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * Command set is the user-facing BATADV_CMD_* doit set defined in
 * <linux/batman_adv.h>.  The header's *_INFO / *_HARDIFS aliases share
 * numeric values with their GET_MESH / GET_HARDIF originals, so listing
 * the canonical names is sufficient to cover both spellings.  No event-
 * only (*_NTF) commands exist in batadv's uapi enum.
 */
static const struct genl_cmd_grammar batadv_cmds[] = {
	{ BATADV_CMD_GET_MESH,			"BATADV_CMD_GET_MESH" },
	{ BATADV_CMD_TP_METER,			"BATADV_CMD_TP_METER" },
	{ BATADV_CMD_TP_METER_CANCEL,		"BATADV_CMD_TP_METER_CANCEL" },
	{ BATADV_CMD_GET_ROUTING_ALGOS,		"BATADV_CMD_GET_ROUTING_ALGOS" },
	{ BATADV_CMD_GET_HARDIF,		"BATADV_CMD_GET_HARDIF" },
	{ BATADV_CMD_GET_TRANSTABLE_LOCAL,	"BATADV_CMD_GET_TRANSTABLE_LOCAL" },
	{ BATADV_CMD_GET_TRANSTABLE_GLOBAL,	"BATADV_CMD_GET_TRANSTABLE_GLOBAL" },
	{ BATADV_CMD_GET_ORIGINATORS,		"BATADV_CMD_GET_ORIGINATORS" },
	{ BATADV_CMD_GET_NEIGHBORS,		"BATADV_CMD_GET_NEIGHBORS" },
	{ BATADV_CMD_GET_GATEWAYS,		"BATADV_CMD_GET_GATEWAYS" },
	{ BATADV_CMD_GET_BLA_CLAIM,		"BATADV_CMD_GET_BLA_CLAIM" },
	{ BATADV_CMD_GET_BLA_BACKBONE,		"BATADV_CMD_GET_BLA_BACKBONE" },
	{ BATADV_CMD_GET_DAT_CACHE,		"BATADV_CMD_GET_DAT_CACHE" },
	{ BATADV_CMD_GET_MCAST_FLAGS,		"BATADV_CMD_GET_MCAST_FLAGS" },
	{ BATADV_CMD_SET_MESH,			"BATADV_CMD_SET_MESH" },
	{ BATADV_CMD_SET_HARDIF,		"BATADV_CMD_SET_HARDIF" },
	{ BATADV_CMD_GET_VLAN,			"BATADV_CMD_GET_VLAN" },
	{ BATADV_CMD_SET_VLAN,			"BATADV_CMD_SET_VLAN" },
};

/*
 * Attribute spec follows the BATADV_ATTR_* enum in <linux/batman_adv.h>.
 * The MESH / HARDIF interface triples (IFINDEX + IFNAME + ADDRESS) and
 * the per-row table identifiers route batman-adv's getter dispatcher;
 * the SET_MESH / SET_HARDIF / SET_VLAN tunables (AGGREGATED_OGMS,
 * AP_ISOLATION, BONDING, BRIDGE_LOOP_AVOIDANCE, DISTRIBUTED_ARP_TABLE,
 * FRAGMENTATION, GW_BANDWIDTH_UP / DOWN, GW_MODE, GW_SEL_CLASS,
 * HOP_PENALTY, LOG_LEVEL, MULTICAST_FORCEFLOOD_ENABLED, MULTICAST_FANOUT,
 * NETWORK_CODING, ORIG_INTERVAL, ELP_INTERVAL, THROUGHPUT_OVERRIDE) feed
 * the setter chains; the throughput-meter result attrs (TPMETER_*) and
 * the per-table row attrs (TT_*, BLA_*, DAT_CACHE_*, MCAST_FLAGS{,_PRIV})
 * are emitted by the dump responses and exercise the validator's
 * "ignore on input" branch the same way the FOU peer-side / OVS STATS
 * attrs do.  VERSION / ALGO_NAME / various IFNAME attrs are STRINGs;
 * MAC-address attrs are 6-byte BINARY blobs; PAD is a 0-byte BINARY
 * alignment partner.  ACTIVE / FLAG_BEST / BLA_OWN are presence-only
 * flags.  None of these are nested containers, so the table stays flat.
 */
static const struct nla_attr_spec batadv_attrs[] = {
	{ BATADV_ATTR_VERSION,				NLA_KIND_STRING, 32 },
	{ BATADV_ATTR_ALGO_NAME,			NLA_KIND_STRING, 32 },
	{ BATADV_ATTR_MESH_IFINDEX,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_MESH_IFNAME,			NLA_KIND_STRING, 16 },
	{ BATADV_ATTR_MESH_ADDRESS,			NLA_KIND_BINARY, 6 },
	{ BATADV_ATTR_HARD_IFINDEX,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_HARD_IFNAME,			NLA_KIND_STRING, 16 },
	{ BATADV_ATTR_HARD_ADDRESS,			NLA_KIND_BINARY, 6 },
	{ BATADV_ATTR_ORIG_ADDRESS,			NLA_KIND_BINARY, 6 },
	{ BATADV_ATTR_TPMETER_RESULT,			NLA_KIND_U8,     1 },
	{ BATADV_ATTR_TPMETER_TEST_TIME,		NLA_KIND_U32,    4 },
	{ BATADV_ATTR_TPMETER_BYTES,			NLA_KIND_U64,    8 },
	{ BATADV_ATTR_TPMETER_COOKIE,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_PAD,				NLA_KIND_BINARY, 0 },
	{ BATADV_ATTR_ACTIVE,				NLA_KIND_FLAG,   0 },
	{ BATADV_ATTR_TT_ADDRESS,			NLA_KIND_BINARY, 6 },
	{ BATADV_ATTR_TT_TTVN,				NLA_KIND_U8,     1 },
	{ BATADV_ATTR_TT_LAST_TTVN,			NLA_KIND_U8,     1 },
	{ BATADV_ATTR_TT_CRC32,				NLA_KIND_U32,    4 },
	{ BATADV_ATTR_TT_VID,				NLA_KIND_U16,    2 },
	{ BATADV_ATTR_TT_FLAGS,				NLA_KIND_U32,    4 },
	{ BATADV_ATTR_FLAG_BEST,			NLA_KIND_FLAG,   0 },
	{ BATADV_ATTR_LAST_SEEN_MSECS,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_NEIGH_ADDRESS,			NLA_KIND_BINARY, 6 },
	{ BATADV_ATTR_TQ,				NLA_KIND_U8,     1 },
	{ BATADV_ATTR_THROUGHPUT,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_BANDWIDTH_UP,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_BANDWIDTH_DOWN,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_ROUTER,				NLA_KIND_BINARY, 6 },
	{ BATADV_ATTR_BLA_OWN,				NLA_KIND_FLAG,   0 },
	{ BATADV_ATTR_BLA_ADDRESS,			NLA_KIND_BINARY, 6 },
	{ BATADV_ATTR_BLA_VID,				NLA_KIND_U16,    2 },
	{ BATADV_ATTR_BLA_BACKBONE,			NLA_KIND_BINARY, 6 },
	{ BATADV_ATTR_BLA_CRC,				NLA_KIND_U16,    2 },
	{ BATADV_ATTR_DAT_CACHE_IP4ADDRESS,		NLA_KIND_U32,    4 },
	{ BATADV_ATTR_DAT_CACHE_HWADDRESS,		NLA_KIND_BINARY, 6 },
	{ BATADV_ATTR_DAT_CACHE_VID,			NLA_KIND_U16,    2 },
	{ BATADV_ATTR_MCAST_FLAGS,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_MCAST_FLAGS_PRIV,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_VLANID,				NLA_KIND_U16,    2 },
	{ BATADV_ATTR_AGGREGATED_OGMS_ENABLED,		NLA_KIND_U8,     1 },
	{ BATADV_ATTR_AP_ISOLATION_ENABLED,		NLA_KIND_U8,     1 },
	{ BATADV_ATTR_ISOLATION_MARK,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_ISOLATION_MASK,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_BONDING_ENABLED,			NLA_KIND_U8,     1 },
	{ BATADV_ATTR_BRIDGE_LOOP_AVOIDANCE_ENABLED,	NLA_KIND_U8,     1 },
	{ BATADV_ATTR_DISTRIBUTED_ARP_TABLE_ENABLED,	NLA_KIND_U8,     1 },
	{ BATADV_ATTR_FRAGMENTATION_ENABLED,		NLA_KIND_U8,     1 },
	{ BATADV_ATTR_GW_BANDWIDTH_DOWN,		NLA_KIND_U32,    4 },
	{ BATADV_ATTR_GW_BANDWIDTH_UP,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_GW_MODE,				NLA_KIND_U8,     1 },
	{ BATADV_ATTR_GW_SEL_CLASS,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_HOP_PENALTY,			NLA_KIND_U8,     1 },
	{ BATADV_ATTR_LOG_LEVEL,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_MULTICAST_FORCEFLOOD_ENABLED,	NLA_KIND_U8,     1 },
	{ BATADV_ATTR_NETWORK_CODING_ENABLED,		NLA_KIND_U8,     1 },
	{ BATADV_ATTR_ORIG_INTERVAL,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_ELP_INTERVAL,			NLA_KIND_U32,    4 },
	{ BATADV_ATTR_THROUGHPUT_OVERRIDE,		NLA_KIND_U32,    4 },
	{ BATADV_ATTR_MULTICAST_FANOUT,			NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_batadv = {
	.name = BATADV_NL_NAME,
	.cmds = batadv_cmds,
	.n_cmds = ARRAY_SIZE(batadv_cmds),
	.attrs = batadv_attrs,
	.n_attrs = ARRAY_SIZE(batadv_attrs),
	.default_version = 1,
};

#endif /* __has_include(<linux/batman_adv.h>) */
