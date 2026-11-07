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

/*
 * l2tp has one policy, l2tp_nl_policy, which every op validates liberally,
 * and a dump's attributes go unparsed, so each op takes the attributes its
 * handler reads.  Tunnel and session ids are drawn from 1 to L2TP_ID_MAX,
 * so that a tunnel or session op, or a SESSION_CREATE, names one that a
 * create made.
 */
#define L2TP_ID_MAX	8

/*
 * l2tp_nl_cmd_tunnel_create() answers -EINVAL without the two conn ids,
 * PROTO_VERSION and ENCAP_TYPE, which has to be UDP or IP, and then wants
 * FD, the socket of a managed tunnel, or an address pair, IPv6 before
 * IPv4, for the socket it makes itself, which a mark cannot say.  That
 * socket binds to the source address, which has to be the host's or any
 * for the bind to succeed, so the IPv4 pair is any or loopback, read with
 * nla_get_in_addr() in network order.  The version is 2 or 3, and
 * UDP_CSUM is read as a flag.  The IPv6 addresses are NLA_BINARYs of up
 * to 16 bytes, which the handler reads as 16.
 */
static const unsigned int l2tp_versions[] = { 2, 3 };
static const unsigned int l2tp_inaddrs[] = { INADDR_ANY, INADDR_LOOPBACK };

static const struct nla_attr_spec l2tp_tunnel_create_attrs[] = {
	{ L2TP_ATTR_CONN_ID,		NLA_KIND_U32_RANGE, L2TP_ID_MAX, 1,
	  .required = true },
	{ L2TP_ATTR_PEER_CONN_ID,	NLA_KIND_U32_RANGE, L2TP_ID_MAX, 1,
	  .required = true },
	{ L2TP_ATTR_PROTO_VERSION,	NLA_KIND_U8_ONEOF, 0, 0,
	  .oneof = l2tp_versions, .n_oneof = ARRAY_SIZE(l2tp_versions),
	  .required = true },
	{ L2TP_ATTR_ENCAP_TYPE,		NLA_KIND_U16_RANGE, L2TP_ENCAPTYPE_IP,
	  L2TP_ENCAPTYPE_UDP, .required = true },
	{ L2TP_ATTR_FD,			NLA_KIND_U32,    4 },
	{ L2TP_ATTR_IP_SADDR,		NLA_KIND_BE32_ONEOF, 0, 0,
	  .oneof = l2tp_inaddrs, .n_oneof = ARRAY_SIZE(l2tp_inaddrs) },
	{ L2TP_ATTR_IP_DADDR,		NLA_KIND_BE32_ONEOF, 0, 0,
	  .oneof = l2tp_inaddrs, .n_oneof = ARRAY_SIZE(l2tp_inaddrs) },
	{ L2TP_ATTR_IP6_SADDR,		NLA_KIND_BINARY, 16 },
	{ L2TP_ATTR_IP6_DADDR,		NLA_KIND_BINARY, 16 },
	{ L2TP_ATTR_UDP_SPORT,		NLA_KIND_U16,    2 },
	{ L2TP_ATTR_UDP_DPORT,		NLA_KIND_U16,    2 },
	{ L2TP_ATTR_UDP_CSUM,		NLA_KIND_U8,     1 },
	{ L2TP_ATTR_UDP_ZERO_CSUM6_TX,	NLA_KIND_FLAG,   0 },
	{ L2TP_ATTR_UDP_ZERO_CSUM6_RX,	NLA_KIND_FLAG,   0 },
};

/* TUNNEL_DELETE, TUNNEL_MODIFY and TUNNEL_GET find the tunnel by its conn
 * id alone. */
static const struct nla_attr_spec l2tp_tunnel_attrs[] = {
	{ L2TP_ATTR_CONN_ID,		NLA_KIND_U32_RANGE, L2TP_ID_MAX, 1 },
};

/*
 * l2tp_nl_cmd_session_create() answers -EINVAL without the tunnel's conn
 * id, the two session ids and PW_TYPE, and -EPROTONOSUPPORT to a type no
 * pseudowire module registers, ETH and PPP being the two that do, or to
 * one other than PPP in an L2TPv2 tunnel.  An L2TPv3 session also takes
 * an L2SPEC_TYPE of NONE or DEFAULT, cookies of up to 8 bytes and the
 * IFNAME of an ETH session's device.
 */
static const unsigned int l2tp_pwtypes[] = { L2TP_PWTYPE_ETH, L2TP_PWTYPE_PPP };

static const struct nla_attr_spec l2tp_session_create_attrs[] = {
	{ L2TP_ATTR_CONN_ID,		NLA_KIND_U32_RANGE, L2TP_ID_MAX, 1,
	  .required = true },
	{ L2TP_ATTR_SESSION_ID,		NLA_KIND_U32_RANGE, L2TP_ID_MAX, 1,
	  .required = true },
	{ L2TP_ATTR_PEER_SESSION_ID,	NLA_KIND_U32_RANGE, L2TP_ID_MAX, 1,
	  .required = true },
	{ L2TP_ATTR_PW_TYPE,		NLA_KIND_U16_ONEOF, 0, 0,
	  .oneof = l2tp_pwtypes, .n_oneof = ARRAY_SIZE(l2tp_pwtypes),
	  .required = true },
	{ L2TP_ATTR_L2SPEC_TYPE,	NLA_KIND_U8_RANGE, L2TP_L2SPECTYPE_DEFAULT,
	  L2TP_L2SPECTYPE_NONE },
	{ L2TP_ATTR_COOKIE,		NLA_KIND_BINARY, 8 },
	{ L2TP_ATTR_PEER_COOKIE,	NLA_KIND_BINARY, 8 },
	{ L2TP_ATTR_IFNAME,		NLA_KIND_STRING, 15, 1 },
	{ L2TP_ATTR_RECV_SEQ,		NLA_KIND_U8,     1 },
	{ L2TP_ATTR_SEND_SEQ,		NLA_KIND_U8,     1 },
	{ L2TP_ATTR_LNS_MODE,		NLA_KIND_U8,     1 },
	{ L2TP_ATTR_RECV_TIMEOUT,	NLA_KIND_U64,    8 },
};

/*
 * The other session ops find the session by IFNAME, or failing that by the
 * conn and session ids, and answer -ENODEV without either; the ids, the way
 * to a session a create made, are marked.  SESSION_MODIFY sets the
 * sequencing, the LNS mode and the reorder timeout.
 */
static const struct nla_attr_spec l2tp_session_attrs[] = {
	{ L2TP_ATTR_CONN_ID,		NLA_KIND_U32_RANGE, L2TP_ID_MAX, 1,
	  .required = true },
	{ L2TP_ATTR_SESSION_ID,		NLA_KIND_U32_RANGE, L2TP_ID_MAX, 1,
	  .required = true },
	{ L2TP_ATTR_IFNAME,		NLA_KIND_STRING, 15, 1 },
};

static const struct nla_attr_spec l2tp_session_modify_attrs[] = {
	{ L2TP_ATTR_CONN_ID,		NLA_KIND_U32_RANGE, L2TP_ID_MAX, 1,
	  .required = true },
	{ L2TP_ATTR_SESSION_ID,		NLA_KIND_U32_RANGE, L2TP_ID_MAX, 1,
	  .required = true },
	{ L2TP_ATTR_IFNAME,		NLA_KIND_STRING, 15, 1 },
	{ L2TP_ATTR_RECV_SEQ,		NLA_KIND_U8,     1 },
	{ L2TP_ATTR_SEND_SEQ,		NLA_KIND_U8,     1 },
	{ L2TP_ATTR_LNS_MODE,		NLA_KIND_U8,     1 },
	{ L2TP_ATTR_RECV_TIMEOUT,	NLA_KIND_U64,    8 },
};

static const struct genl_cmd_grammar l2tp_cmds[] = {
	{ L2TP_CMD_NOOP,		"L2TP_CMD_NOOP", genl_no_attrs },
	{ L2TP_CMD_TUNNEL_CREATE,	"L2TP_CMD_TUNNEL_CREATE",
	  l2tp_tunnel_create_attrs, ARRAY_SIZE(l2tp_tunnel_create_attrs) },
	{ L2TP_CMD_TUNNEL_DELETE,	"L2TP_CMD_TUNNEL_DELETE",
	  l2tp_tunnel_attrs, ARRAY_SIZE(l2tp_tunnel_attrs) },
	{ L2TP_CMD_TUNNEL_MODIFY,	"L2TP_CMD_TUNNEL_MODIFY",
	  l2tp_tunnel_attrs, ARRAY_SIZE(l2tp_tunnel_attrs) },
	{ L2TP_CMD_TUNNEL_GET,		"L2TP_CMD_TUNNEL_GET",
	  l2tp_tunnel_attrs, ARRAY_SIZE(l2tp_tunnel_attrs) },
	{ L2TP_CMD_SESSION_CREATE,	"L2TP_CMD_SESSION_CREATE",
	  l2tp_session_create_attrs, ARRAY_SIZE(l2tp_session_create_attrs) },
	{ L2TP_CMD_SESSION_DELETE,	"L2TP_CMD_SESSION_DELETE",
	  l2tp_session_attrs, ARRAY_SIZE(l2tp_session_attrs) },
	{ L2TP_CMD_SESSION_MODIFY,	"L2TP_CMD_SESSION_MODIFY",
	  l2tp_session_modify_attrs, ARRAY_SIZE(l2tp_session_modify_attrs) },
	{ L2TP_CMD_SESSION_GET,		"L2TP_CMD_SESSION_GET",
	  l2tp_session_attrs, ARRAY_SIZE(l2tp_session_attrs) },
};

struct genl_family_grammar fam_l2tp = {
	.name = L2TP_GENL_NAME,
	.cmds = l2tp_cmds,
	.n_cmds = ARRAY_SIZE(l2tp_cmds),
	.default_version = L2TP_GENL_VERSION,
};

#endif /* __has_include(<linux/l2tp.h>) */
