/*
 * Genetlink family grammar: netdev (per-device, queue, NAPI and page-pool
 * introspection plus the dmabuf bind ops), targeting net/core/netdev-genl.c
 * and netdev-genl-gen.c.  NAPI_SET and QUEUE_CREATE are GENL_ADMIN_PERM and
 * BIND_RX is GENL_UNS_ADMIN_PERM, the rest carry no flag.  The per-command
 * NETDEV_A_* namespaces overlap at low ids, so an op takes the table of its
 * own policy.
 */

#if __has_include(<linux/netdev.h>)

#include "kernel/netdev.h"
#include "netlink-genl-families.h"
#include "utils.h"

#include "kernel/socket.h"

/*
 * The nests, from netdev_queue_id_nl_policy, netdev_page_pool_info_nl_policy
 * and netdev_lease_nl_policy.  A page pool's id is an NLA_UINT, so 4 or 8
 * bytes.  The handlers answer -EINVAL to a queue nest without its id and
 * type, a lease without its ifindex and queue, and a page pool stats
 * request without the pool's id, so those are marked required.
 */
static const struct nla_attr_spec netdev_queue_id_attrs[] = {
	{ NETDEV_A_QUEUE_ID,		NLA_KIND_U32,    4, .required = true },
	{ NETDEV_A_QUEUE_TYPE,		NLA_KIND_U32_RANGE, 1, 0,
	  .required = true },
};

static const struct nla_attr_spec netdev_page_pool_info_attrs[] = {
	{ NETDEV_A_PAGE_POOL_ID,	NLA_KIND_BINARY_FIXED2, 8, 4,
	  .required = true },
	{ NETDEV_A_PAGE_POOL_IFINDEX,	NLA_KIND_U32_RANGE, INT32_MAX, 1 },
};

static const struct nla_attr_spec netdev_lease_attrs[] = {
	{ NETDEV_A_LEASE_IFINDEX,	NLA_KIND_U32_RANGE, UINT32_MAX, 1,
	  .required = true },
	{ NETDEV_A_LEASE_QUEUE,		NLA_KIND_NESTED, 0, 0,
	  netdev_queue_id_attrs, ARRAY_SIZE(netdev_queue_id_attrs),
	  .required = true },
	{ NETDEV_A_LEASE_NETNS_ID,	NLA_KIND_U32_RANGE, INT32_MAX, 0 },
};

/*
 * The ops validate strictly against a policy of their own, a dumpit's
 * apart from its doit's, and each ends at its own last id, so a request
 * meets only the ids of its cmd's: a dump of QUEUE_GET has no QUEUE_ID and
 * a NAPI_GET doit no IFINDEX.  What the replies carry, the counters, the
 * XDP features and the ids of a queue's NAPI, is not in a request policy.
 * The bounded u32s draw inside their bounds, an ifindex from 1 and a queue
 * type of 0 or 1 among them, and the NETNS_ID s32 from 0; an NLA_UINT's
 * bound, and RX_PAGE_SIZE's floor, the kernel's PAGE_SIZE, are not
 * modelled.  QUEUE_GET's doit, QUEUE_CREATE, NAPI_SET and the two binds
 * answer -EINVAL without the attributes they look up, which are marked
 * required; the single-attribute tables need no mark.
 */
static const struct nla_attr_spec netdev_dev_get_attrs[] = {
	{ NETDEV_A_DEV_IFINDEX,		NLA_KIND_U32_RANGE, UINT32_MAX, 1 },
};

static const struct nla_attr_spec netdev_page_pool_get_attrs[] = {
	{ NETDEV_A_PAGE_POOL_ID,	NLA_KIND_BINARY_FIXED2, 8, 4 },
};

static const struct nla_attr_spec netdev_page_pool_get_dump_attrs[] = {
	{ NETDEV_A_PAGE_POOL_IFINDEX,	NLA_KIND_U32_RANGE, INT32_MAX, 1 },
};

static const struct nla_attr_spec netdev_page_pool_stats_get_attrs[] = {
	{ NETDEV_A_PAGE_POOL_STATS_INFO, NLA_KIND_NESTED, 0, 0,
	  netdev_page_pool_info_attrs, ARRAY_SIZE(netdev_page_pool_info_attrs) },
};

static const struct nla_attr_spec netdev_queue_get_attrs[] = {
	{ NETDEV_A_QUEUE_ID,		NLA_KIND_U32,    4, .required = true },
	{ NETDEV_A_QUEUE_IFINDEX,	NLA_KIND_U32_RANGE, UINT32_MAX, 1,
	  .required = true },
	{ NETDEV_A_QUEUE_TYPE,		NLA_KIND_U32_RANGE, 1, 0,
	  .required = true },
};

static const struct nla_attr_spec netdev_queue_get_dump_attrs[] = {
	{ NETDEV_A_QUEUE_IFINDEX,	NLA_KIND_U32_RANGE, UINT32_MAX, 1 },
};

static const struct nla_attr_spec netdev_queue_create_attrs[] = {
	{ NETDEV_A_QUEUE_IFINDEX,	NLA_KIND_U32_RANGE, UINT32_MAX, 1,
	  .required = true },
	{ NETDEV_A_QUEUE_TYPE,		NLA_KIND_U32_RANGE, 1, 0,
	  .required = true },
	{ NETDEV_A_QUEUE_LEASE,		NLA_KIND_NESTED, 0, 0,
	  netdev_lease_attrs, ARRAY_SIZE(netdev_lease_attrs),
	  .required = true },
};

static const struct nla_attr_spec netdev_napi_get_attrs[] = {
	{ NETDEV_A_NAPI_ID,		NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec netdev_napi_get_dump_attrs[] = {
	{ NETDEV_A_NAPI_IFINDEX,	NLA_KIND_U32_RANGE, UINT32_MAX, 1 },
};

/* The two timeouts are NLA_UINT, 4 or 8 bytes. */
static const struct nla_attr_spec netdev_napi_set_attrs[] = {
	{ NETDEV_A_NAPI_ID,		NLA_KIND_U32,    4, .required = true },
	{ NETDEV_A_NAPI_DEFER_HARD_IRQS, NLA_KIND_U32_RANGE, INT32_MAX, 0 },
	{ NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT, NLA_KIND_BINARY_FIXED2, 8, 4 },
	{ NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT, NLA_KIND_BINARY_FIXED2, 8, 4 },
	{ NETDEV_A_NAPI_THREADED,	NLA_KIND_U32_RANGE, 2, 0 },
};

/* QSTATS_GET is a dumpit alone.  SCOPE is an NLA_UINT, 4 or 8 bytes. */
static const struct nla_attr_spec netdev_qstats_get_attrs[] = {
	{ NETDEV_A_QSTATS_IFINDEX,	NLA_KIND_U32_RANGE, UINT32_MAX, 1 },
	{ NETDEV_A_QSTATS_SCOPE,	NLA_KIND_BINARY_FIXED2, 8, 4 },
};

static const struct nla_attr_spec netdev_bind_rx_attrs[] = {
	{ NETDEV_A_DMABUF_IFINDEX,	NLA_KIND_U32_RANGE, UINT32_MAX, 1,
	  .required = true },
	{ NETDEV_A_DMABUF_QUEUES,	NLA_KIND_NESTED, 0, 0,
	  netdev_queue_id_attrs, ARRAY_SIZE(netdev_queue_id_attrs),
	  .required = true },
	{ NETDEV_A_DMABUF_FD,		NLA_KIND_U32,    4, .required = true },
	{ NETDEV_A_DMABUF_RX_PAGE_SIZE,	NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec netdev_bind_tx_attrs[] = {
	{ NETDEV_A_DMABUF_IFINDEX,	NLA_KIND_U32_RANGE, UINT32_MAX, 1,
	  .required = true },
	{ NETDEV_A_DMABUF_FD,		NLA_KIND_U32,    4, .required = true },
};

/* The dumpit of DEV_GET has no policy, which the genl core gives a
 * reject-all one, so a dump of it takes no attribute. */
static const struct genl_cmd_grammar netdev_cmds[] = {
	{ NETDEV_CMD_DEV_GET,             "NETDEV_CMD_DEV_GET",
	  netdev_dev_get_attrs, ARRAY_SIZE(netdev_dev_get_attrs),
	  genl_no_attrs },
	{ NETDEV_CMD_PAGE_POOL_GET,       "NETDEV_CMD_PAGE_POOL_GET",
	  netdev_page_pool_get_attrs, ARRAY_SIZE(netdev_page_pool_get_attrs),
	  netdev_page_pool_get_dump_attrs,
	  ARRAY_SIZE(netdev_page_pool_get_dump_attrs) },
	{ NETDEV_CMD_PAGE_POOL_STATS_GET, "NETDEV_CMD_PAGE_POOL_STATS_GET",
	  netdev_page_pool_stats_get_attrs,
	  ARRAY_SIZE(netdev_page_pool_stats_get_attrs) },
	{ NETDEV_CMD_QUEUE_GET,           "NETDEV_CMD_QUEUE_GET",
	  netdev_queue_get_attrs, ARRAY_SIZE(netdev_queue_get_attrs),
	  netdev_queue_get_dump_attrs,
	  ARRAY_SIZE(netdev_queue_get_dump_attrs) },
	{ NETDEV_CMD_QUEUE_CREATE,        "NETDEV_CMD_QUEUE_CREATE",
	  netdev_queue_create_attrs, ARRAY_SIZE(netdev_queue_create_attrs) },
	{ NETDEV_CMD_NAPI_GET,            "NETDEV_CMD_NAPI_GET",
	  netdev_napi_get_attrs, ARRAY_SIZE(netdev_napi_get_attrs),
	  netdev_napi_get_dump_attrs, ARRAY_SIZE(netdev_napi_get_dump_attrs) },
	{ NETDEV_CMD_NAPI_SET,            "NETDEV_CMD_NAPI_SET",
	  netdev_napi_set_attrs, ARRAY_SIZE(netdev_napi_set_attrs) },
	{ NETDEV_CMD_QSTATS_GET,          "NETDEV_CMD_QSTATS_GET",
	  netdev_qstats_get_attrs, ARRAY_SIZE(netdev_qstats_get_attrs) },
	{ NETDEV_CMD_BIND_RX,             "NETDEV_CMD_BIND_RX",
	  netdev_bind_rx_attrs, ARRAY_SIZE(netdev_bind_rx_attrs) },
	{ NETDEV_CMD_BIND_TX,             "NETDEV_CMD_BIND_TX",
	  netdev_bind_tx_attrs, ARRAY_SIZE(netdev_bind_tx_attrs) },
};

struct genl_family_grammar fam_netdev = {
	.name = "netdev",
	.cmds = netdev_cmds,
	.n_cmds = ARRAY_SIZE(netdev_cmds),
	.default_version = 1,
};

#endif /* __has_include(<linux/netdev.h>) */
