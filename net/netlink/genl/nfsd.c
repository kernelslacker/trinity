/*
 * Genetlink family grammar: nfsd (kernel NFS server control plane),
 * targeting fs/nfsd/netlink.c and nfsctl.c.  Every op but RPC_STATUS_GET,
 * SERVER_STATS_GET and the THREADS / VERSION / LISTENER / POOL_MODE
 * getters is GENL_ADMIN_PERM.  An op with a policy has a table of its
 * own; one without takes no attribute.
 */

#if __has_include(<linux/nfsd_netlink.h>)

#include "kernel/nfsd_netlink.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * The nests of the export cache requests, from nfsd_svc_export_nl_policy,
 * nfsd_expkey_nl_policy and the policies under them: FSLOCATIONS nests
 * LOCATION nests HOST and PATH, SECINFO nests PSEUDOFLAVOR and FLAGS.  UUID
 * is exactly 16 bytes to nfsd_nl_parse_one_export().  FSID is an s32 in
 * svc_export and a blob in expkey.  The *_FLAGS and XPRTSEC words are
 * NLA_POLICY_MASK: 0x3ffff, one bit for each of the 18 export flags, on both
 * FLAGS words, and 0x7, the three xprtsec modes, on XPRTSEC.
 *
 * nfsd_nl_parse_one_export() answers an export with no CLIENT, PATH or EXPIRY
 * -EINVAL, nfsd_nl_parse_one_expkey() a key with no CLIENT, FSIDTYPE, FSID or
 * EXPIRY, and nfsd_nl_parse_fslocations() a location without both HOST and
 * PATH, so those are marked required.
 */
static const struct nla_attr_spec nfsd_fslocation_attrs[] = {
	{ NFSD_A_FSLOCATION_HOST,	NLA_KIND_STRING, 32, 1, .required = true },
	{ NFSD_A_FSLOCATION_PATH,	NLA_KIND_STRING, 64, 1, .required = true },
};

static const struct nla_attr_spec nfsd_fslocations_attrs[] = {
	{ NFSD_A_FSLOCATIONS_LOCATION,	NLA_KIND_NESTED, 0, 0,
	  nfsd_fslocation_attrs, ARRAY_SIZE(nfsd_fslocation_attrs) },
};

static const struct nla_attr_spec nfsd_auth_flavor_attrs[] = {
	{ NFSD_A_AUTH_FLAVOR_PSEUDOFLAVOR, NLA_KIND_U32, 4 },
	{ NFSD_A_AUTH_FLAVOR_FLAGS,	NLA_KIND_U32_MASK, 0x3ffff },
};

static const struct nla_attr_spec nfsd_svc_export_attrs[] = {
	{ NFSD_A_SVC_EXPORT_SEQNO,	NLA_KIND_U64,    8 },
	{ NFSD_A_SVC_EXPORT_CLIENT,	NLA_KIND_STRING, 32, 1, .required = true },
	{ NFSD_A_SVC_EXPORT_PATH,	NLA_KIND_STRING, 64, 1, .required = true },
	{ NFSD_A_SVC_EXPORT_NEGATIVE,	NLA_KIND_FLAG,   0 },
	{ NFSD_A_SVC_EXPORT_EXPIRY,	NLA_KIND_U64,    8, .required = true },
	{ NFSD_A_SVC_EXPORT_ANON_UID,	NLA_KIND_U32,    4 },
	{ NFSD_A_SVC_EXPORT_ANON_GID,	NLA_KIND_U32,    4 },
	{ NFSD_A_SVC_EXPORT_FSLOCATIONS, NLA_KIND_NESTED, 0, 0,
	  nfsd_fslocations_attrs, ARRAY_SIZE(nfsd_fslocations_attrs) },
	{ NFSD_A_SVC_EXPORT_UUID,	NLA_KIND_BINARY_FIXED2, 16, 16 },
	{ NFSD_A_SVC_EXPORT_SECINFO,	NLA_KIND_NESTED, 0, 0,
	  nfsd_auth_flavor_attrs, ARRAY_SIZE(nfsd_auth_flavor_attrs) },
	{ NFSD_A_SVC_EXPORT_XPRTSEC,	NLA_KIND_U32_MASK, 0x7 },
	{ NFSD_A_SVC_EXPORT_FLAGS,	NLA_KIND_U32_MASK, 0x3ffff },
	{ NFSD_A_SVC_EXPORT_FSID,	NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec nfsd_expkey_attrs[] = {
	{ NFSD_A_EXPKEY_SEQNO,		NLA_KIND_U64,    8 },
	{ NFSD_A_EXPKEY_CLIENT,		NLA_KIND_STRING, 32, 1, .required = true },
	{ NFSD_A_EXPKEY_FSIDTYPE,	NLA_KIND_U8,     1, .required = true },
	{ NFSD_A_EXPKEY_FSID,		NLA_KIND_BINARY, 32, .required = true },
	{ NFSD_A_EXPKEY_NEGATIVE,	NLA_KIND_FLAG,   0 },
	{ NFSD_A_EXPKEY_EXPIRY,		NLA_KIND_U64,    8, .required = true },
	{ NFSD_A_EXPKEY_PATH,		NLA_KIND_STRING, 64, 1 },
};

/* nfsd_nl_version_set_doit() skips a version that has no MAJOR. */
static const struct nla_attr_spec nfsd_version_attrs[] = {
	{ NFSD_A_VERSION_MAJOR,		NLA_KIND_U32,    4, .required = true },
	{ NFSD_A_VERSION_MINOR,		NLA_KIND_U32,    4 },
	{ NFSD_A_VERSION_ENABLED,	NLA_KIND_FLAG,   0 },
};

/* ADDR is a sockaddr_in or a sockaddr_in6, which nfsd_nl_listener_set_doit()
 * sizes by its family.  nfsd_nl_validate_listeners() answers a socket
 * without both ADDR and TRANSPORT_NAME -EINVAL. */
static const struct nla_attr_spec nfsd_sock_attrs[] = {
	{ NFSD_A_SOCK_ADDR,		NLA_KIND_BINARY_FIXED2, 28, 16,
	  .required = true },
	{ NFSD_A_SOCK_TRANSPORT_NAME,	NLA_KIND_STRING, 16, 1,
	  .required = true },
};

/*
 * The ops validate strictly against their nfsd_*_nl_policy, so an id it
 * has no slot for costs an -EINVAL, and every namespace starts at 1: a
 * cmd takes only the ids of its own.  The two the replies add, SOCK_RPCBIND
 * and POOL_MODE_NPOOLS, are not in a request policy.  FH_KEY is exactly
 * 16 bytes, the rest u32 or NLA_NUL_STRING.  THREADS_SET answers -EINVAL
 * without THREADS, or with a GRACETIME or LEASETIME outside [10, 3600],
 * which its policy leaves plain u32s.  The cmds that take one attribute,
 * POOL_MODE_SET and the three UNLOCKs, want it, and a table of one is
 * drawn from by every request that has an attribute, so they mark nothing.
 */
static const struct nla_attr_spec nfsd_threads_set_attrs[] = {
	{ NFSD_A_SERVER_THREADS,	NLA_KIND_U32,    4, .required = true },
	{ NFSD_A_SERVER_GRACETIME,	NLA_KIND_U32_RANGE, 3600, 10 },
	{ NFSD_A_SERVER_LEASETIME,	NLA_KIND_U32_RANGE, 3600, 10 },
	{ NFSD_A_SERVER_SCOPE,		NLA_KIND_STRING, 16, 1 },
	{ NFSD_A_SERVER_MIN_THREADS,	NLA_KIND_U32,    4 },
	{ NFSD_A_SERVER_FH_KEY,		NLA_KIND_BINARY_FIXED2, 16, 16 },
};

static const struct nla_attr_spec nfsd_version_set_attrs[] = {
	{ NFSD_A_SERVER_PROTO_VERSION,	NLA_KIND_NESTED, 0, 0,
	  nfsd_version_attrs, ARRAY_SIZE(nfsd_version_attrs) },
};

static const struct nla_attr_spec nfsd_listener_set_attrs[] = {
	{ NFSD_A_SERVER_SOCK_ADDR,	NLA_KIND_NESTED, 0, 0,
	  nfsd_sock_attrs, ARRAY_SIZE(nfsd_sock_attrs) },
	{ NFSD_A_SERVER_SOCK_USERSPACE_RPCBIND, NLA_KIND_FLAG, 0 },
};

static const struct nla_attr_spec nfsd_pool_mode_set_attrs[] = {
	{ NFSD_A_POOL_MODE_MODE,	NLA_KIND_STRING, 16, 1 },
};

static const struct nla_attr_spec nfsd_svc_export_set_reqs_attrs[] = {
	{ NFSD_A_SVC_EXPORT_REQS_REQUESTS, NLA_KIND_NESTED, 0, 0,
	  nfsd_svc_export_attrs, ARRAY_SIZE(nfsd_svc_export_attrs) },
};

static const struct nla_attr_spec nfsd_expkey_set_reqs_attrs[] = {
	{ NFSD_A_EXPKEY_REQS_REQUESTS,	NLA_KIND_NESTED, 0, 0,
	  nfsd_expkey_attrs, ARRAY_SIZE(nfsd_expkey_attrs) },
};

/* MASK holds one bit for each cache type: svc_export and expkey. */
static const struct nla_attr_spec nfsd_cache_flush_attrs[] = {
	{ NFSD_A_CACHE_FLUSH_MASK,	NLA_KIND_U32_MASK, 0x3 },
};

/* ADDRESS is NLA_POLICY_MIN_LEN(16): a sockaddr_in or sockaddr_in6. */
static const struct nla_attr_spec nfsd_unlock_ip_attrs[] = {
	{ NFSD_A_UNLOCK_IP_ADDRESS,	NLA_KIND_BINARY_FIXED2, 28, 16 },
};

static const struct nla_attr_spec nfsd_unlock_filesystem_attrs[] = {
	{ NFSD_A_UNLOCK_FILESYSTEM_PATH, NLA_KIND_STRING, 64, 1 },
};

static const struct nla_attr_spec nfsd_unlock_export_attrs[] = {
	{ NFSD_A_UNLOCK_EXPORT_PATH,	NLA_KIND_STRING, 64, 1 },
};

/*
 * The getters, the dumps and RPC_STATUS_GET have no policy, which the genl
 * core gives a reject-all one, so they take no attribute; what the replies
 * carry, the RPC_STATUS_* and SERVER_STATS_* ids, is not a request's.
 */
static const struct genl_cmd_grammar nfsd_cmds[] = {
	{ NFSD_CMD_RPC_STATUS_GET,      "NFSD_CMD_RPC_STATUS_GET", genl_no_attrs },
	{ NFSD_CMD_THREADS_SET,         "NFSD_CMD_THREADS_SET",
	  nfsd_threads_set_attrs, ARRAY_SIZE(nfsd_threads_set_attrs) },
	{ NFSD_CMD_THREADS_GET,         "NFSD_CMD_THREADS_GET", genl_no_attrs },
	{ NFSD_CMD_VERSION_SET,         "NFSD_CMD_VERSION_SET",
	  nfsd_version_set_attrs, ARRAY_SIZE(nfsd_version_set_attrs) },
	{ NFSD_CMD_VERSION_GET,         "NFSD_CMD_VERSION_GET", genl_no_attrs },
	{ NFSD_CMD_LISTENER_SET,        "NFSD_CMD_LISTENER_SET",
	  nfsd_listener_set_attrs, ARRAY_SIZE(nfsd_listener_set_attrs) },
	{ NFSD_CMD_LISTENER_GET,        "NFSD_CMD_LISTENER_GET", genl_no_attrs },
	{ NFSD_CMD_POOL_MODE_SET,       "NFSD_CMD_POOL_MODE_SET",
	  nfsd_pool_mode_set_attrs, ARRAY_SIZE(nfsd_pool_mode_set_attrs) },
	{ NFSD_CMD_POOL_MODE_GET,       "NFSD_CMD_POOL_MODE_GET", genl_no_attrs },
	/* Not an op: a kernel-to-user multicast event, so the demuxer
	 * answers -EOPNOTSUPP.  Kept on purpose: reaching that rejection
	 * is demuxer coverage, and the id is right if a doit handler
	 * ever appears. */
	{ NFSD_CMD_CACHE_NOTIFY,        "NFSD_CMD_CACHE_NOTIFY", genl_no_attrs },
	{ NFSD_CMD_SVC_EXPORT_GET_REQS, "NFSD_CMD_SVC_EXPORT_GET_REQS", genl_no_attrs },
	{ NFSD_CMD_SVC_EXPORT_SET_REQS, "NFSD_CMD_SVC_EXPORT_SET_REQS",
	  nfsd_svc_export_set_reqs_attrs,
	  ARRAY_SIZE(nfsd_svc_export_set_reqs_attrs) },
	{ NFSD_CMD_EXPKEY_GET_REQS,     "NFSD_CMD_EXPKEY_GET_REQS", genl_no_attrs },
	{ NFSD_CMD_EXPKEY_SET_REQS,     "NFSD_CMD_EXPKEY_SET_REQS",
	  nfsd_expkey_set_reqs_attrs, ARRAY_SIZE(nfsd_expkey_set_reqs_attrs) },
	{ NFSD_CMD_CACHE_FLUSH,         "NFSD_CMD_CACHE_FLUSH",
	  nfsd_cache_flush_attrs, ARRAY_SIZE(nfsd_cache_flush_attrs) },
	{ NFSD_CMD_UNLOCK_IP,           "NFSD_CMD_UNLOCK_IP",
	  nfsd_unlock_ip_attrs, ARRAY_SIZE(nfsd_unlock_ip_attrs) },
	{ NFSD_CMD_UNLOCK_FILESYSTEM,   "NFSD_CMD_UNLOCK_FILESYSTEM",
	  nfsd_unlock_filesystem_attrs, ARRAY_SIZE(nfsd_unlock_filesystem_attrs) },
	{ NFSD_CMD_UNLOCK_EXPORT,       "NFSD_CMD_UNLOCK_EXPORT",
	  nfsd_unlock_export_attrs, ARRAY_SIZE(nfsd_unlock_export_attrs) },
	{ NFSD_CMD_SERVER_STATS_GET,    "NFSD_CMD_SERVER_STATS_GET", genl_no_attrs },
};

struct genl_family_grammar fam_nfsd = {
	.name = NFSD_FAMILY_NAME,
	.cmds = nfsd_cmds,
	.n_cmds = ARRAY_SIZE(nfsd_cmds),
	.default_version = NFSD_FAMILY_VERSION,
};

#endif /* __has_include(<linux/nfsd_netlink.h>) */
