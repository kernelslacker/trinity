/*
 * Genetlink family grammar: netdev.
 *
 * The "netdev" generic-netlink family exposes per-device introspection
 * (NETDEV_CMD_DEV_GET), per-queue / per-NAPI enumeration
 * (NETDEV_CMD_QUEUE_GET, NETDEV_CMD_NAPI_GET), per-queue statistics
 * (NETDEV_CMD_QSTATS_GET), and the AF_XDP socket attach plumbing
 * (NETDEV_CMD_BIND_RX, NETDEV_CMD_BIND_TX).  The latter two reach the
 * page-pool / dmabuf binding path and the XSK queue wire-up code that
 * sit behind netdev_nl_bind_rx_doit() / netdev_nl_bind_tx_doit().
 *
 * Without a grammar entry, random nlmsg_type IDs essentially never
 * match the runtime-assigned family_id for "netdev", so the per-cmd
 * netdev_nl_*_policy walker plus the bind / page-pool handlers stay
 * cold under generic netlink fuzzing.  Resolving the family at first
 * NETLINK_GENERIC use lets the message generator address real netdev
 * messages whose attribute shapes plausibly survive the per-cmd policy.
 *
 * The netdev family uses several disjoint NETDEV_A_* namespaces (DEV,
 * NAPI, QUEUE, QSTATS, PAGE_POOL, DMABUF), one per command group, each
 * starting at type id 1 with an IFINDEX-shaped u32.  Following the
 * ethtool exemplar's position-overlap trick, the flat nla_attr_spec
 * table below seeds the low-numbered positions with U32 entries from
 * whichever namespace makes them likely to validate: position 1 is
 * IFINDEX in five of the six namespaces, positions 2-4 are an
 * id/index/scope mix that the per-cmd policy accepts as u32 across
 * most commands.  Higher positions cover the queue/dmabuf/page-pool
 * specifics so messages targeting those commands also reach the deeper
 * handlers.
 *
 * Header gating mirrors the fou / mptcp_pm families: <linux/netdev.h>
 * is the upstream UAPI header carrying every NETDEV_CMD_* and
 * NETDEV_A_* enum referenced below.  Build hosts lacking the header
 * silently drop the family from the registry instead of failing the
 * build.  Per-symbol #ifndef shims fill in NETDEV_CMD_* / NETDEV_A_*
 * on build hosts whose stale uapi predates the BIND_RX / BIND_TX /
 * QSTATS_GET commands and the DMABUF attribute namespace.
 */

#if __has_include(<linux/netdev.h>)

#include "kernel/netdev.h"
#include "netlink-genl-families.h"
#include "utils.h"

#include "kernel/socket.h"
static const struct genl_cmd_grammar netdev_cmds[] = {
	{ NETDEV_CMD_DEV_GET,     "NETDEV_CMD_DEV_GET" },
	{ NETDEV_CMD_QUEUE_GET,   "NETDEV_CMD_QUEUE_GET" },
	{ NETDEV_CMD_NAPI_GET,    "NETDEV_CMD_NAPI_GET" },
	{ NETDEV_CMD_QSTATS_GET,  "NETDEV_CMD_QSTATS_GET" },
	{ NETDEV_CMD_BIND_RX,     "NETDEV_CMD_BIND_RX" },
	{ NETDEV_CMD_BIND_TX,     "NETDEV_CMD_BIND_TX" },
};

/*
 * Attribute spec table.  The netdev family uses six disjoint
 * NETDEV_A_* namespaces (DEV / NAPI / QUEUE / QSTATS / PAGE_POOL /
 * DMABUF) but every one of them puts an IFINDEX-shaped u32 at type
 * position 1, which makes a single NETDEV_A_DEV_IFINDEX entry at
 * position 1 valid for every command in the cmds[] table above.
 *
 * Positions 2-4 are intentionally seeded with constants whose numeric
 * values cover the most common shapes across the per-cmd policies:
 *   2 (NAPI_ID / IFINDEX / QUEUE_TYPE / DMABUF_QUEUES): U32 is the
 *     majority — BIND_RX's DMABUF_QUEUES is the one NESTED outlier and
 *     is covered by the DMABUF_QUEUES entry below.
 *   3 (QUEUE_TYPE / FD / NAPI_ID / SCOPE): U32 across all five
 *     command namespaces that put something here.
 *   4 (SCOPE / DMABUF_ID / NAPI_ID): U32 across all of them.
 *
 * Higher positions cover the BIND_RX (DMABUF) and NAPI_SET (NAPI)
 * payload shapes so messages targeting those commands plausibly
 * survive the per-cmd validator and reach netdev_nl_bind_rx_doit() /
 * netdev_nl_napi_set_doit() with usable arguments rather than
 * bouncing off the policy gate.
 */
static const struct nla_attr_spec netdev_attrs[] = {
	{ NETDEV_A_DEV_IFINDEX,            NLA_KIND_U32,    4 },
	{ NETDEV_A_NAPI_ID,                NLA_KIND_U32,    4 },
	{ NETDEV_A_QUEUE_TYPE,             NLA_KIND_U32,    4 },
	{ NETDEV_A_QSTATS_SCOPE,           NLA_KIND_U32,    4 },
	{ NETDEV_A_PAGE_POOL_NAPI_ID,      NLA_KIND_U32,    4 },
	{ NETDEV_A_DMABUF_QUEUES,          NLA_KIND_NESTED, 0 },
	{ NETDEV_A_DMABUF_FD,              NLA_KIND_U32,    4 },
	{ NETDEV_A_DMABUF_ID,              NLA_KIND_U32,    4 },
	{ NETDEV_A_NAPI_DEFER_HARD_IRQS,   NLA_KIND_U32,    4 },
	{ NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT, NLA_KIND_U64,    8 },
};

struct genl_family_grammar fam_netdev = {
	.name = "netdev",
	.cmds = netdev_cmds,
	.n_cmds = ARRAY_SIZE(netdev_cmds),
	.attrs = netdev_attrs,
	.n_attrs = ARRAY_SIZE(netdev_attrs),
	.default_version = 1,
};

#endif /* __has_include(<linux/netdev.h>) */
