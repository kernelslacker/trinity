/*
 * Genetlink family grammar: l2tp.
 *
 * The L2TPv3 control plane is a single generic-netlink family
 * (L2TP_GENL_NAME = "l2tp") whose nine commands cover the full
 * tunnel/session lifecycle: TUNNEL_CREATE/DELETE/MODIFY/GET and
 * SESSION_CREATE/DELETE/MODIFY/GET, plus a CMD_NOOP slot.  The
 * per-cmd nla_policy parsers live in net/l2tp/l2tp_netlink.c, and
 * the post-parse handlers (l2tp_nl_cmd_tunnel_create / _delete,
 * l2tp_nl_cmd_session_create / _delete, ...) drive a refcounted
 * state machine — l2tp_tunnel_get / l2tp_session_get walk a
 * per-netns IDR with refcount_inc_not_zero, and the create/delete
 * paths flip ->dead and unhash via l2tp_tunnel_delete /
 * l2tp_session_delete.  That refcount + dead-flag dance has been
 * the source of multiple historic UAFs (the l2tp_tunnel_destruct
 * race family; CVE-2020-25670 / -25671 reference-leak on the IPv6
 * setsockopt path; the l2tp_session_get_by_ifname leak), and the
 * netlink path is the cleanest way for a fuzzer to drive create
 * and delete operations interleaved against random tunnel/session
 * IDs.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-
 * assigned family_id for "l2tp", so the parser plus the
 * create/delete dispatchers have been routinely cold under
 * generic netlink fuzzing; the controller-resolved family_id
 * dispatcher addresses real l2tp messages whose attribute shapes
 * plausibly survive the per-cmd policy.  Random CONN_ID /
 * SESSION_ID values cause the post-parse handler to bail with
 * -ENOENT, but that's after the full attribute tree has been
 * walked and refcount lookups have been attempted, so coverage
 * of the parser and the IDR walk is preserved.
 *
 * Per the wireguard / tipc model, a single flat nla_attr_spec
 * table lists every id used by any nest reachable from this
 * family's commands.  L2TP_ATTR_STATS opens a sub-namespace
 * (L2TP_ATTR_TX_PACKETS / TX_BYTES / RX_PACKETS / ...) whose
 * numeric ids collide with outer L2TP_ATTR_* ids — L2TP_ATTR_TX_PACKETS=1
 * vs L2TP_ATTR_PW_TYPE=1, L2TP_ATTR_TX_BYTES=2 vs L2TP_ATTR_ENCAP_TYPE=2,
 * etc.  The kernel only validates each child against the policy
 * of whichever nest is currently being walked, so the collisions
 * are harmless and the single flat table is the same shape
 * wireguard / tipc / mptcp_pm use.
 *
 * Header gating mirrors the wireguard family: <linux/l2tp.h> is
 * the upstream UAPI header that ships with kernel headers from
 * 2.6.35 onward, but a few attribute ids were appended later
 * (the IPv6 saddr/daddr pair plus UDP_ZERO_CSUM6_TX/RX in 3.16,
 * RX_COOKIE_DISCARDS in 4.4, RX_INVALID and the *_PAD ids in 4.7).
 * Build hosts whose sysroot lacks <linux/l2tp.h> entirely silently
 * drop the family from the registry; build hosts whose header
 * predates one of the late-add attributes pick up the numeric
 * fallback in compat.h instead of failing the build.
 */

#if __has_include(<linux/l2tp.h>)

/* <netinet/in.h> directly first to set _NETINET_IN_H, so the libc-compat
 * guards in <linux/in.h> + <linux/in6.h> (pulled in by <linux/l2tp.h>)
 * suppress the struct in_addr / sockaddr_in / IPPROTO_* duplicates.
 * compat.h then comes after <linux/l2tp.h> so its #ifndef L2TP_ATTR_*
 * shims see the host header's enum values and only fill in the late-add
 * ids the host header actually omits. */
#include <netinet/in.h>

#include <linux/l2tp.h>

#include "compat.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar l2tp_cmds[] = {
	{ L2TP_CMD_NOOP,		"L2TP_CMD_NOOP" },
	{ L2TP_CMD_TUNNEL_CREATE,	"L2TP_CMD_TUNNEL_CREATE" },
	{ L2TP_CMD_TUNNEL_DELETE,	"L2TP_CMD_TUNNEL_DELETE" },
	{ L2TP_CMD_TUNNEL_MODIFY,	"L2TP_CMD_TUNNEL_MODIFY" },
	{ L2TP_CMD_TUNNEL_GET,		"L2TP_CMD_TUNNEL_GET" },
	{ L2TP_CMD_SESSION_CREATE,	"L2TP_CMD_SESSION_CREATE" },
	{ L2TP_CMD_SESSION_DELETE,	"L2TP_CMD_SESSION_DELETE" },
	{ L2TP_CMD_SESSION_MODIFY,	"L2TP_CMD_SESSION_MODIFY" },
	{ L2TP_CMD_SESSION_GET,		"L2TP_CMD_SESSION_GET" },
};

/*
 * Attribute spec follows the per-nest enums in <linux/l2tp.h>.
 * Outer L2TP_ATTR_* covers the tunnel/session selector ids
 * (CONN_ID + PEER_CONN_ID + SESSION_ID + PEER_SESSION_ID), the
 * pseudowire/encap/protocol scalars, the IFNAME for L2TPv3-eth
 * sessions, the UDP source/dest ports + IPv4/IPv6 saddr/daddr
 * tuple consumed by l2tp_tunnel_create, the COOKIE / PEER_COOKIE
 * variable-length blobs (0/4/8 bytes per RFC 3931), and the
 * L2TP_ATTR_STATS NESTED that opens the inner counter namespace.
 *
 * Inner L2TP_ATTR_* (under STATS) carries u64 packet/byte/error
 * counters per direction.  The kernel only emits these in the
 * GET responses, so the ids are pure response-side payloads;
 * listing them here exercises the validator's "ignore on input"
 * branch the same way the OVS dp/flow STATS attrs do.
 *
 * Variable-length sizes:
 *   IFNAME           IFNAMSIZ - 1 (NUL_STRING upper bound)
 *   COOKIE / PEER_COOKIE  8 (RFC 3931 max; kernel accepts 0/4/8)
 *   IP6_SADDR / IP6_DADDR 16 (struct in6_addr)
 */
static const struct nla_attr_spec l2tp_attrs[] = {
	/* L2TP_ATTR_* — outer */
	{ L2TP_ATTR_PW_TYPE,			NLA_KIND_U16,    2 },
	{ L2TP_ATTR_ENCAP_TYPE,			NLA_KIND_U16,    2 },
	{ L2TP_ATTR_OFFSET,			NLA_KIND_U16,    2 },
	{ L2TP_ATTR_DATA_SEQ,			NLA_KIND_U16,    2 },
	{ L2TP_ATTR_L2SPEC_TYPE,		NLA_KIND_U8,     1 },
	{ L2TP_ATTR_L2SPEC_LEN,			NLA_KIND_U8,     1 },
	{ L2TP_ATTR_PROTO_VERSION,		NLA_KIND_U8,     1 },
	{ L2TP_ATTR_IFNAME,			NLA_KIND_STRING, 15 },
	{ L2TP_ATTR_CONN_ID,			NLA_KIND_U32,    4 },
	{ L2TP_ATTR_PEER_CONN_ID,		NLA_KIND_U32,    4 },
	{ L2TP_ATTR_SESSION_ID,			NLA_KIND_U32,    4 },
	{ L2TP_ATTR_PEER_SESSION_ID,		NLA_KIND_U32,    4 },
	{ L2TP_ATTR_UDP_CSUM,			NLA_KIND_U8,     1 },
	{ L2TP_ATTR_VLAN_ID,			NLA_KIND_U16,    2 },
	{ L2TP_ATTR_COOKIE,			NLA_KIND_BINARY, 8 },
	{ L2TP_ATTR_PEER_COOKIE,		NLA_KIND_BINARY, 8 },
	{ L2TP_ATTR_DEBUG,			NLA_KIND_U32,    4 },
	{ L2TP_ATTR_RECV_SEQ,			NLA_KIND_U8,     1 },
	{ L2TP_ATTR_SEND_SEQ,			NLA_KIND_U8,     1 },
	{ L2TP_ATTR_LNS_MODE,			NLA_KIND_U8,     1 },
	{ L2TP_ATTR_USING_IPSEC,		NLA_KIND_U8,     1 },
	{ L2TP_ATTR_RECV_TIMEOUT,		NLA_KIND_U64,    8 },
	{ L2TP_ATTR_FD,				NLA_KIND_U32,    4 },
	{ L2TP_ATTR_IP_SADDR,			NLA_KIND_U32,    4 },
	{ L2TP_ATTR_IP_DADDR,			NLA_KIND_U32,    4 },
	{ L2TP_ATTR_UDP_SPORT,			NLA_KIND_U16,    2 },
	{ L2TP_ATTR_UDP_DPORT,			NLA_KIND_U16,    2 },
	{ L2TP_ATTR_MTU,			NLA_KIND_U16,    2 },
	{ L2TP_ATTR_MRU,			NLA_KIND_U16,    2 },
	{ L2TP_ATTR_STATS,			NLA_KIND_NESTED, 0 },
	{ L2TP_ATTR_IP6_SADDR,			NLA_KIND_BINARY, 16 },
	{ L2TP_ATTR_IP6_DADDR,			NLA_KIND_BINARY, 16 },
	{ L2TP_ATTR_UDP_ZERO_CSUM6_TX,		NLA_KIND_FLAG,   0 },
	{ L2TP_ATTR_UDP_ZERO_CSUM6_RX,		NLA_KIND_FLAG,   0 },

	/* L2TP_ATTR_* (under L2TP_ATTR_STATS) — inner.  IDs intentionally
	 * overlap with the outer L2TP_ATTR_* namespace; the kernel only
	 * matches each child against the policy of the currently-walked
	 * nest, so collisions are harmless. */
	{ L2TP_ATTR_TX_PACKETS,			NLA_KIND_U64,    8 },
	{ L2TP_ATTR_TX_BYTES,			NLA_KIND_U64,    8 },
	{ L2TP_ATTR_TX_ERRORS,			NLA_KIND_U64,    8 },
	{ L2TP_ATTR_RX_PACKETS,			NLA_KIND_U64,    8 },
	{ L2TP_ATTR_RX_BYTES,			NLA_KIND_U64,    8 },
	{ L2TP_ATTR_RX_SEQ_DISCARDS,		NLA_KIND_U64,    8 },
	{ L2TP_ATTR_RX_OOS_PACKETS,		NLA_KIND_U64,    8 },
	{ L2TP_ATTR_RX_ERRORS,			NLA_KIND_U64,    8 },
	{ L2TP_ATTR_RX_COOKIE_DISCARDS,		NLA_KIND_U64,    8 },
	{ L2TP_ATTR_RX_INVALID,			NLA_KIND_U64,    8 },
};

struct genl_family_grammar fam_l2tp = {
	.name = L2TP_GENL_NAME,
	.cmds = l2tp_cmds,
	.n_cmds = ARRAY_SIZE(l2tp_cmds),
	.attrs = l2tp_attrs,
	.n_attrs = ARRAY_SIZE(l2tp_attrs),
	.default_version = L2TP_GENL_VERSION,
};

#endif /* __has_include(<linux/l2tp.h>) */
