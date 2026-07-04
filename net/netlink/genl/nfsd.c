/*
 * Genetlink family grammar: nfsd (kernel NFS server control plane).
 *
 * The nfsd subsystem exposes its userspace control plane through a
 * single generic-netlink family ("nfsd") carrying nine commands: a
 * dumpit-only RPC_STATUS_GET that enumerates per-RPC service stats,
 * paired *_GET / *_SET commands for the server-wide thread / version
 * / listener / pool-mode controls, and the THREADS_GET variant that
 * carries no input attrs.  The four user-callable SET commands are
 * GENL_ADMIN_PERM (CAP_SYS_NICE-equivalent gated) but the per-cmd
 * nla_policy walker runs before the capability check, so the
 * validator coverage lands unprivileged -- penetrating the family
 * demuxer with a real family_id puts every per-cmd parser directly in
 * the fuzzer's reach.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "nfsd", so the per-cmd nla_policy walker in
 * fs/nfsd/nfsctl.c plus the threads / version / listener / pool-mode
 * doit handlers have been routinely cold under generic netlink
 * fuzzing; resolving the family at first NETLINK_GENERIC use lets
 * the message generator address real nfsd messages whose attribute
 * shapes plausibly survive the per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample model,
 * a single flat nla_attr_spec table lists every id used by this
 * family's commands.  nfsd unusually carries four distinct top-level
 * attribute namespaces -- NFSD_A_SERVER_* (THREADS_SET), NFSD_A_
 * SERVER_PROTO_VERSION (VERSION_SET outer wrapping NFSD_A_VERSION_*),
 * NFSD_A_SERVER_SOCK_ADDR (LISTENER_SET outer wrapping NFSD_A_SOCK_*),
 * and NFSD_A_POOL_MODE_* (POOL_MODE_SET) -- whose ids all start at 1
 * with disagreeing nla_kind values (U32 vs NESTED vs NESTED vs
 * NUL_STRING).  The flat table cannot disambiguate overlapping keys,
 * so following the handshake / dpll / ovpn precedent only the
 * NFSD_A_SERVER_* surface plus the NFSD_A_RPC_STATUS_* response-side
 * namespace (whose ids 5..14 do not collide with any other namespace)
 * are enumerated here: SERVER_* is the only namespace whose ids 1..4
 * carry consistent kinds across every attribute the THREADS_SET
 * parser ingests.  The NESTED-anchored VERSION_SET / LISTENER_SET and
 * the POOL_MODE_SET-side NUL_STRING-at-1 belong in a future grammar
 * extension that carries a per-command attribute namespace; their
 * cmds are still in the cmds[] table below and will start exercising
 * their inner parsers once the per-command namespace lands.
 *
 * The family carries a nonzero declared version (NFSD_FAMILY_VERSION
 * = 1) so the default_version member is initialised -- the kernel's
 * dispatcher doesn't gate on the genlmsghdr.version byte today, but
 * matching the declared family version keeps the message generator
 * honest against any future version-gated dispatch.  hdrsize stays 0:
 * nfsd has no family-specific fixed header, attributes follow the
 * genlmsghdr directly.
 *
 * Header gating mirrors the team / hsr / fou / psample families:
 * <linux/nfsd_netlink.h> is the upstream UAPI header carrying every
 * NFSD_CMD_* and NFSD_A_* enum referenced below.  Build hosts lacking
 * the header silently drop the family from the registry instead of
 * failing the build.  Per-symbol #ifndef shims in
 * include/kernel/nfsd_netlink.h fill in any ids missing from a stale
 * uapi.
 */

#if __has_include(<linux/nfsd_netlink.h>)

#include "kernel/nfsd_netlink.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar nfsd_cmds[] = {
	{ NFSD_CMD_RPC_STATUS_GET, "NFSD_CMD_RPC_STATUS_GET" },
	{ NFSD_CMD_THREADS_SET,    "NFSD_CMD_THREADS_SET" },
	{ NFSD_CMD_THREADS_GET,    "NFSD_CMD_THREADS_GET" },
	{ NFSD_CMD_VERSION_SET,    "NFSD_CMD_VERSION_SET" },
	{ NFSD_CMD_VERSION_GET,    "NFSD_CMD_VERSION_GET" },
	{ NFSD_CMD_LISTENER_SET,   "NFSD_CMD_LISTENER_SET" },
	{ NFSD_CMD_LISTENER_GET,   "NFSD_CMD_LISTENER_GET" },
	{ NFSD_CMD_POOL_MODE_SET,  "NFSD_CMD_POOL_MODE_SET" },
	{ NFSD_CMD_POOL_MODE_GET,  "NFSD_CMD_POOL_MODE_GET" },
};

/*
 * Attribute spec follows the NFSD_A_SERVER_* + NFSD_A_RPC_STATUS_*
 * enums in <linux/nfsd_netlink.h>.  Ids 1..3 are u32 scalars covering
 * the THREADS_SET surface (THREADS = nfsd thread-pool target count,
 * GRACETIME / LEASETIME = NFSv4 grace / lease seconds) that overlap
 * cleanly with the RPC_STATUS dump response u32 ids (XID / FLAGS /
 * PROG).  Id 4 is a NUL_STRING for THREADS_SET's SERVER_SCOPE selector
 * -- the RPC_STATUS_VERSION u32 at id 4 disagrees on kind but is
 * response-only, so it lands on the validator's "ignore on input"
 * branch the same way the fou / psample / handshake grammars do.
 * Ids 5..14 are response-side payloads emitted by RPC_STATUS_GET:
 * PROC and COMPOUND_OPS are u32 RPC opcode selectors, SERVICE_TIME
 * is a u64 nanoseconds counter, PAD is the alignment partner for the
 * SERVICE_TIME u64 (zero-byte payload matches the wire shape), the
 * SADDR4 / DADDR4 pair are __be32 IPv4 endpoint addresses, SADDR6 /
 * DADDR6 are 16-byte IPv6 endpoint addresses, and the SPORT / DPORT
 * pair are __be16 wire-encoded port numbers.  Listing them all here
 * exercises the validator's "ignore on input" branch and the
 * dispatch-then-discard accounting in nfsd_nl_rpc_status_get_dumpit
 * the same way the fou / psample response-side enumerations do.
 *
 * Not enumerated: NFSD_A_SERVER_PROTO_VERSION (id 1, NESTED) for
 * VERSION_SET, NFSD_A_SERVER_SOCK_ADDR (id 1, NESTED) for LISTENER_
 * SET, NFSD_A_POOL_MODE_MODE (id 1, NUL_STRING) for POOL_MODE_SET --
 * all three disagree with NFSD_A_SERVER_THREADS (id 1, U32) on kind
 * and a single flat table cannot carry both.  Per the handshake
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
