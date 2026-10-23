/*
 * Genetlink family grammar: nfsd (kernel NFS server control plane),
 * targeting fs/nfsd/netlink.c and nfsctl.c.  Every op but RPC_STATUS_GET,
 * SERVER_STATS_GET and the THREADS / VERSION / LISTENER / POOL_MODE
 * getters is GENL_ADMIN_PERM.  Only the NFSD_A_SERVER_* and
 * NFSD_A_RPC_STATUS_* namespaces are listed; the attribute table says why.
 */

#if __has_include(<linux/nfsd_netlink.h>)

#include "kernel/nfsd_netlink.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar nfsd_cmds[] = {
	{ NFSD_CMD_RPC_STATUS_GET,      "NFSD_CMD_RPC_STATUS_GET" },
	{ NFSD_CMD_THREADS_SET,         "NFSD_CMD_THREADS_SET" },
	{ NFSD_CMD_THREADS_GET,         "NFSD_CMD_THREADS_GET" },
	{ NFSD_CMD_VERSION_SET,         "NFSD_CMD_VERSION_SET" },
	{ NFSD_CMD_VERSION_GET,         "NFSD_CMD_VERSION_GET" },
	{ NFSD_CMD_LISTENER_SET,        "NFSD_CMD_LISTENER_SET" },
	{ NFSD_CMD_LISTENER_GET,        "NFSD_CMD_LISTENER_GET" },
	{ NFSD_CMD_POOL_MODE_SET,       "NFSD_CMD_POOL_MODE_SET" },
	{ NFSD_CMD_POOL_MODE_GET,       "NFSD_CMD_POOL_MODE_GET" },
	/* Not an op: a kernel-to-user multicast event, so the demuxer
	 * answers -EOPNOTSUPP.  Kept on purpose: reaching that rejection
	 * is demuxer coverage, and the id is right if a doit handler
	 * ever appears. */
	{ NFSD_CMD_CACHE_NOTIFY,        "NFSD_CMD_CACHE_NOTIFY" },
	{ NFSD_CMD_SVC_EXPORT_GET_REQS, "NFSD_CMD_SVC_EXPORT_GET_REQS" },
	{ NFSD_CMD_SVC_EXPORT_SET_REQS, "NFSD_CMD_SVC_EXPORT_SET_REQS" },
	{ NFSD_CMD_EXPKEY_GET_REQS,     "NFSD_CMD_EXPKEY_GET_REQS" },
	{ NFSD_CMD_EXPKEY_SET_REQS,     "NFSD_CMD_EXPKEY_SET_REQS" },
	{ NFSD_CMD_CACHE_FLUSH,         "NFSD_CMD_CACHE_FLUSH" },
	{ NFSD_CMD_UNLOCK_IP,           "NFSD_CMD_UNLOCK_IP" },
	{ NFSD_CMD_UNLOCK_FILESYSTEM,   "NFSD_CMD_UNLOCK_FILESYSTEM" },
	{ NFSD_CMD_UNLOCK_EXPORT,       "NFSD_CMD_UNLOCK_EXPORT" },
	{ NFSD_CMD_SERVER_STATS_GET,    "NFSD_CMD_SERVER_STATS_GET" },
};

/*
 * Attribute spec follows the NFSD_A_SERVER_* + NFSD_A_RPC_STATUS_*
 * enums in <linux/nfsd_netlink.h>.  Ids 1..3 are u32 scalars covering
 * the THREADS_SET surface (THREADS = nfsd thread-pool target count,
 * GRACETIME / LEASETIME = NFSv4 grace / lease seconds) that overlap
 * cleanly with the RPC_STATUS dump response u32 ids (XID / FLAGS /
 * PROG).  Id 4 is a NUL_STRING for THREADS_SET's SERVER_SCOPE selector
 * -- the RPC_STATUS_VERSION u32 at id 4 disagrees on kind but is
 * response-only, so the entry follows SCOPE.  The ops validate
 * strictly, so every op but THREADS_SET answers an id 4 with -EINVAL.
 * Ids 5..14 are response-side payloads emitted by RPC_STATUS_GET:
 * PROC and COMPOUND_OPS are u32 RPC opcode selectors, SERVICE_TIME
 * is a u64 nanoseconds counter, PAD is the alignment partner for the
 * SERVICE_TIME u64 (zero-byte payload matches the wire shape), the
 * SADDR4 / DADDR4 pair are __be32 IPv4 endpoint addresses, SADDR6 /
 * DADDR6 are 16-byte IPv6 endpoint addresses, and the SPORT / DPORT
 * pair are __be16 wire-encoded port numbers.  Listing them costs an
 * -EINVAL on every op whose policy has no slot for them; RPC_STATUS_GET,
 * which emits them, has no policy and takes no attributes.
 *
 * NFSD_A_CACHE_NOTIFY_CACHE_TYPE (id 1, U32) and NFSD_A_CACHE_FLUSH_
 * MASK (id 1, U32) are consistent with the existing id 1 U32 entry;
 * no new table slot is required.  NFSD_CMD_CACHE_NOTIFY is a kernel-
 * originated multicast event (mcgrp exportd) with no input policy;
 * NFSD_CMD_CACHE_FLUSH carries the single MASK attr whose masked-U32
 * constraint the existing slot satisfies on kind.
 *
 * Not enumerated: NFSD_A_SERVER_PROTO_VERSION (id 1, NESTED) for
 * VERSION_SET, NFSD_A_SERVER_SOCK_ADDR (id 1, NESTED) for LISTENER_
 * SET, NFSD_A_POOL_MODE_MODE (id 1, NUL_STRING) for POOL_MODE_SET,
 * NFSD_A_SVC_EXPORT_REQS_REQUESTS (id 1, NESTED) for SVC_EXPORT_GET/
 * SET_REQS, NFSD_A_EXPKEY_REQS_REQUESTS (id 1, NESTED) for EXPKEY_
 * GET/SET_REQS, NFSD_A_UNLOCK_IP_ADDRESS (id 1, BINARY) for UNLOCK_
 * IP, NFSD_A_UNLOCK_FILESYSTEM_PATH (id 1, NUL_STRING) for UNLOCK_
 * FILESYSTEM, NFSD_A_UNLOCK_EXPORT_PATH (id 1, NUL_STRING) for
 * UNLOCK_EXPORT, and NFSD_A_SERVER_STATS_RC_HITS (id 1, U64) anchoring
 * the full SERVER_STATS response namespace for SERVER_STATS_GET --
 * every one of these disagrees with NFSD_A_SERVER_THREADS (id 1, U32)
 * on kind and a single flat table cannot carry both.  Per the handshake
 * precedent the larger surface (SERVER_* + RPC_STATUS_*) anchors the
 * grammar and the others wait on a per-command namespace extension.
 */
static const struct nla_attr_spec nfsd_attrs[] = {
	{ NFSD_A_SERVER_THREADS,	    NLA_KIND_U32,    4 },
	{ NFSD_A_SERVER_GRACETIME,	    NLA_KIND_U32,    4 },
	{ NFSD_A_SERVER_LEASETIME,	    NLA_KIND_U32,    4 },
	{ NFSD_A_SERVER_SCOPE,		    NLA_KIND_STRING, 16 },
	{ NFSD_A_RPC_STATUS_PROC,	    NLA_KIND_U32,    4 },
	{ NFSD_A_RPC_STATUS_SERVICE_TIME,   NLA_KIND_U64,    8 },
	{ NFSD_A_RPC_STATUS_PAD,	    NLA_KIND_BINARY, 0 },
	{ NFSD_A_RPC_STATUS_SADDR4,	    NLA_KIND_U32,    4 },
	{ NFSD_A_RPC_STATUS_DADDR4,	    NLA_KIND_U32,    4 },
	{ NFSD_A_RPC_STATUS_SADDR6,	    NLA_KIND_BINARY, 16 },
	{ NFSD_A_RPC_STATUS_DADDR6,	    NLA_KIND_BINARY, 16 },
	{ NFSD_A_RPC_STATUS_SPORT,	    NLA_KIND_U16,    2 },
	{ NFSD_A_RPC_STATUS_DPORT,	    NLA_KIND_U16,    2 },
	{ NFSD_A_RPC_STATUS_COMPOUND_OPS,   NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_nfsd = {
	.name = NFSD_FAMILY_NAME,
	.cmds = nfsd_cmds,
	.n_cmds = ARRAY_SIZE(nfsd_cmds),
	.attrs = nfsd_attrs,
	.n_attrs = ARRAY_SIZE(nfsd_attrs),
	.default_version = NFSD_FAMILY_VERSION,
};

#endif /* __has_include(<linux/nfsd_netlink.h>) */
