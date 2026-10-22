/*
 * Genetlink family grammar: sunrpc (SUNRPC cache upcall control plane),
 * targeting the policies and handlers in net/sunrpc/netlink.c.  Its ops are
 * all GENL_ADMIN_PERM and only the NESTED REQUESTS attribute is listed; the
 * reasons sit at the two tables below.
 */

#if __has_include(<linux/sunrpc_netlink.h>)

#include "kernel/sunrpc_netlink.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * The four *_REQS commands and CACHE_FLUSH are GENL_ADMIN_PERM, which
 * genl_family_rcv_msg() checks before parsing attributes: a child without
 * CAP_NET_ADMIN in the initial user namespace gets -EPERM, while one that
 * holds it reaches every per-cmd parser once the message carries a real
 * family_id.
 */
static const struct genl_cmd_grammar sunrpc_cmds[] = {
	/* Not an op: a kernel-to-user multicast event, so the demuxer
	 * answers -EOPNOTSUPP.  Kept on purpose: reaching that rejection
	 * is demuxer coverage, and the id is right if a doit handler
	 * ever appears. */
	{ SUNRPC_CMD_CACHE_NOTIFY,	  "SUNRPC_CMD_CACHE_NOTIFY" },
	{ SUNRPC_CMD_IP_MAP_GET_REQS,	  "SUNRPC_CMD_IP_MAP_GET_REQS" },
	{ SUNRPC_CMD_IP_MAP_SET_REQS,	  "SUNRPC_CMD_IP_MAP_SET_REQS" },
	{ SUNRPC_CMD_UNIX_GID_GET_REQS,	  "SUNRPC_CMD_UNIX_GID_GET_REQS" },
	{ SUNRPC_CMD_UNIX_GID_SET_REQS,	  "SUNRPC_CMD_UNIX_GID_SET_REQS" },
	{ SUNRPC_CMD_CACHE_FLUSH,	  "SUNRPC_CMD_CACHE_FLUSH" },
};

/*
 * A flat table cannot hold namespaces whose id 1 disagrees on kind, so
 * only the NESTED REQUESTS surface is listed.  SUNRPC_A_IP_MAP_REQS_
 * REQUESTS and SUNRPC_A_UNIX_GID_REQS_REQUESTS are both wire id 1 NESTED,
 * so this one entry covers the outer validators of all four *_REQS
 * commands (the wire id is what the generator emits).
 *
 * Not listed until the grammar carries a per-command attribute
 * namespace: SUNRPC_A_CACHE_NOTIFY_CACHE_TYPE and SUNRPC_A_CACHE_FLUSH_
 * MASK (id 1, U32) and the inner SUNRPC_A_IP_MAP_* / SUNRPC_A_UNIX_GID_*
 * namespaces (ids 1..6 / 1..5), which only appear nested inside
 * REQUESTS.  The two u32-anchored commands stay in cmds[] so the family
 * demuxer still sees them, but their attributes are not modelled.
 */
static const struct nla_attr_spec sunrpc_attrs[] = {
	{ SUNRPC_A_IP_MAP_REQS_REQUESTS,	NLA_KIND_NESTED, 0 },
};

struct genl_family_grammar fam_sunrpc __attribute__((used)) = {
	.name = SUNRPC_FAMILY_NAME,
	.cmds = sunrpc_cmds,
	.n_cmds = ARRAY_SIZE(sunrpc_cmds),
	.attrs = sunrpc_attrs,
	.n_attrs = ARRAY_SIZE(sunrpc_attrs),
	.default_version = SUNRPC_FAMILY_VERSION,
};

#endif /* __has_include(<linux/sunrpc_netlink.h>) */
