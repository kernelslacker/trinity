/*
 * Genetlink family grammar: l2tp (L2TPv3 tunnels and sessions), targeting
 * net/l2tp/l2tp_netlink.c.  Every op but NOOP is GENL_UNS_ADMIN_PERM.
 */

#if __has_include(<linux/l2tp.h>)

/* <netinet/in.h> directly first to set _NETINET_IN_H, so the libc-compat
 * guards in <linux/in.h> + <linux/in6.h> (pulled in by <linux/l2tp.h>)
 * suppress the struct in_addr / sockaddr_in / IPPROTO_* duplicates.
 * include/kernel/l2tp.h then comes after <linux/l2tp.h> so its #ifndef L2TP_ATTR_*
 * shims see the host header's enum values and only fill in the late-add
 * ids the host header actually omits. */
#include <netinet/in.h>

#include <linux/l2tp.h>

#include "netlink-genl-families.h"
#include "utils.h"

#include "kernel/l2tp.h"
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
 * counters per direction.  STATS is a bare NLA_NESTED in l2tp_nl_policy
 * that the kernel only emits and never parses, so on input these ids
 * are checked as the outer attributes sharing them.
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
	 * overlap with the outer L2TP_ATTR_* namespace; the kernel never
	 * walks STATS on input, so a drawn id is checked as the outer
	 * attribute with that id. */
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
