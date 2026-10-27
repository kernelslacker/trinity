/*
 * Genetlink family grammar: sunrpc (SUNRPC cache upcall control plane),
 * targeting the policies and handlers in net/sunrpc/netlink.c.  Its ops are
 * all GENL_ADMIN_PERM; an op with a policy has a table of its own, one
 * without takes no attribute.
 */

#if __has_include(<linux/sunrpc_netlink.h>)

#include "kernel/sunrpc_netlink.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * The nests of the two SET_REQS ops, from sunrpc_ip_map_nl_policy and
 * sunrpc_unix_gid_nl_policy.  The three ip_map strings are NLA_NUL_STRING
 * and GIDS repeats once per gid, a single one being enough to pass.  The
 * entry parsers in net/sunrpc/svcauth_unix.c answer -EINVAL to an ip_map
 * without its CLASS, ADDR or EXPIRY, to a CLASS longer than 8 bytes and to
 * an ADDR that rpc_pton() cannot read, so CLASS is "nfsd", the class nfsd
 * keys its entries by, and ADDR the loopback address; a unix_gid needs its
 * UID and EXPIRY.
 */
static const struct nla_attr_spec sunrpc_ip_map_attrs[] = {
	{ SUNRPC_A_IP_MAP_SEQNO,	NLA_KIND_U64,    8 },
	{ SUNRPC_A_IP_MAP_CLASS,	NLA_KIND_STRING_WORD, 0, 0,
	  .word = "nfsd", .required = true },
	{ SUNRPC_A_IP_MAP_ADDR,		NLA_KIND_STRING_WORD, 0, 0,
	  .word = "127.0.0.1", .required = true },
	{ SUNRPC_A_IP_MAP_DOMAIN,	NLA_KIND_STRING, 32, 1 },
	{ SUNRPC_A_IP_MAP_NEGATIVE,	NLA_KIND_FLAG,   0 },
	{ SUNRPC_A_IP_MAP_EXPIRY,	NLA_KIND_U64,    8,
	  .required = true },
};

static const struct nla_attr_spec sunrpc_unix_gid_attrs[] = {
	{ SUNRPC_A_UNIX_GID_SEQNO,	NLA_KIND_U64,    8 },
	{ SUNRPC_A_UNIX_GID_UID,	NLA_KIND_U32,    4,
	  .required = true },
	{ SUNRPC_A_UNIX_GID_GIDS,	NLA_KIND_U32,    4 },
	{ SUNRPC_A_UNIX_GID_NEGATIVE,	NLA_KIND_FLAG,   0 },
	{ SUNRPC_A_UNIX_GID_EXPIRY,	NLA_KIND_U64,    8,
	  .required = true },
};

/*
 * The ops validate strictly against a policy of their own, and every
 * attribute namespace starts at id 1, so a cmd takes only the ids of its
 * own.  REQUESTS is a nest of one entry's attributes, and the mask of
 * CACHE_FLUSH a u32 the policy holds to its two cache bits.
 */
static const struct nla_attr_spec sunrpc_ip_map_set_reqs_attrs[] = {
	{ SUNRPC_A_IP_MAP_REQS_REQUESTS, NLA_KIND_NESTED, 0, 0,
	  sunrpc_ip_map_attrs, ARRAY_SIZE(sunrpc_ip_map_attrs) },
};

static const struct nla_attr_spec sunrpc_unix_gid_set_reqs_attrs[] = {
	{ SUNRPC_A_UNIX_GID_REQS_REQUESTS, NLA_KIND_NESTED, 0, 0,
	  sunrpc_unix_gid_attrs, ARRAY_SIZE(sunrpc_unix_gid_attrs) },
};

static const struct nla_attr_spec sunrpc_cache_flush_attrs[] = {
	{ SUNRPC_A_CACHE_FLUSH_MASK,	NLA_KIND_U32_MASK, 0x3 },
};

/*
 * The four *_REQS commands and CACHE_FLUSH are GENL_ADMIN_PERM, which
 * genl_family_rcv_msg() checks before parsing attributes: a child without
 * CAP_NET_ADMIN in the initial user namespace gets -EPERM, while one that
 * holds it reaches every per-cmd parser once the message carries a real
 * family_id.
 *
 * The two GET_REQS ops are dumpits with no policy, which the genl core
 * gives a reject-all one, so they take no attribute; the entries their
 * replies carry are not a request's.
 */
static const struct genl_cmd_grammar sunrpc_cmds[] = {
	/* Not an op: a kernel-to-user multicast event, so the demuxer
	 * answers -EOPNOTSUPP.  Kept on purpose: reaching that rejection
	 * is demuxer coverage, and the id is right if a doit handler
	 * ever appears. */
	{ SUNRPC_CMD_CACHE_NOTIFY,	  "SUNRPC_CMD_CACHE_NOTIFY",
	  genl_no_attrs },
	{ SUNRPC_CMD_IP_MAP_GET_REQS,	  "SUNRPC_CMD_IP_MAP_GET_REQS",
	  genl_no_attrs },
	{ SUNRPC_CMD_IP_MAP_SET_REQS,	  "SUNRPC_CMD_IP_MAP_SET_REQS",
	  sunrpc_ip_map_set_reqs_attrs,
	  ARRAY_SIZE(sunrpc_ip_map_set_reqs_attrs) },
	{ SUNRPC_CMD_UNIX_GID_GET_REQS,	  "SUNRPC_CMD_UNIX_GID_GET_REQS",
	  genl_no_attrs },
	{ SUNRPC_CMD_UNIX_GID_SET_REQS,	  "SUNRPC_CMD_UNIX_GID_SET_REQS",
	  sunrpc_unix_gid_set_reqs_attrs,
	  ARRAY_SIZE(sunrpc_unix_gid_set_reqs_attrs) },
	{ SUNRPC_CMD_CACHE_FLUSH,	  "SUNRPC_CMD_CACHE_FLUSH",
	  sunrpc_cache_flush_attrs, ARRAY_SIZE(sunrpc_cache_flush_attrs) },
};

struct genl_family_grammar fam_sunrpc __attribute__((used)) = {
	.name = SUNRPC_FAMILY_NAME,
	.cmds = sunrpc_cmds,
	.n_cmds = ARRAY_SIZE(sunrpc_cmds),
	.default_version = SUNRPC_FAMILY_VERSION,
};

#endif /* __has_include(<linux/sunrpc_netlink.h>) */
