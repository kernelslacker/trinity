/*
 * Genetlink family grammar: netdev (per-device, queue, NAPI and page-pool
 * introspection plus the dmabuf bind ops), targeting net/core/netdev-genl.c
 * and netdev-genl-gen.c.  The per-command NETDEV_A_* namespaces overlap at
 * low ids; the attribute table says how the flat table copes.
 */

#if __has_include(<linux/netdev.h>)

#include "kernel/netdev.h"
#include "netlink-genl-families.h"
#include "utils.h"

#include "kernel/socket.h"

/*
 * Fresh-uapi shims for NETDEV_CMD_* ids that build hosts with a stale
 * <linux/netdev.h> may not yet know.  PAGE_POOL_GET / PAGE_POOL_STATS_GET
 * / NAPI_SET landed at the values below alongside the earlier
 * BIND_RX / BIND_TX / QSTATS_GET additions; QUEUE_CREATE is the newest
 * user-callable command (post-6.18) and takes the next slot after
 * BIND_TX.  Values mirror the mainline enum ordering in
 * include/uapi/linux/netdev.h.
 */
#ifndef NETDEV_CMD_PAGE_POOL_GET
#define NETDEV_CMD_PAGE_POOL_GET       5
#endif
#ifndef NETDEV_CMD_PAGE_POOL_STATS_GET
#define NETDEV_CMD_PAGE_POOL_STATS_GET 9
#endif
#ifndef NETDEV_CMD_NAPI_SET
#define NETDEV_CMD_NAPI_SET            14
#endif
#ifndef NETDEV_CMD_QUEUE_CREATE
#define NETDEV_CMD_QUEUE_CREATE        16
#endif

static const struct genl_cmd_grammar netdev_cmds[] = {
	{ NETDEV_CMD_DEV_GET,             "NETDEV_CMD_DEV_GET" },
	{ NETDEV_CMD_PAGE_POOL_GET,       "NETDEV_CMD_PAGE_POOL_GET" },
	{ NETDEV_CMD_PAGE_POOL_STATS_GET, "NETDEV_CMD_PAGE_POOL_STATS_GET" },
	{ NETDEV_CMD_QUEUE_GET,           "NETDEV_CMD_QUEUE_GET" },
	{ NETDEV_CMD_QUEUE_CREATE,        "NETDEV_CMD_QUEUE_CREATE" },
	{ NETDEV_CMD_NAPI_GET,            "NETDEV_CMD_NAPI_GET" },
	{ NETDEV_CMD_NAPI_SET,            "NETDEV_CMD_NAPI_SET" },
	{ NETDEV_CMD_QSTATS_GET,          "NETDEV_CMD_QSTATS_GET" },
	{ NETDEV_CMD_BIND_RX,             "NETDEV_CMD_BIND_RX" },
	{ NETDEV_CMD_BIND_TX,             "NETDEV_CMD_BIND_TX" },
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
