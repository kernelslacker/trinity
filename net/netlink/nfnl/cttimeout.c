/*
 * NETLINK_NETFILTER subsystem grammar: cttimeout
 * (NFNL_SUBSYS_CTNETLINK_TIMEOUT), targeting
 * net/netfilter/nfnetlink_cttimeout.c.  CTA_TIMEOUT_DATA is a bare NLA_NESTED
 * that only NEW and DEFAULT_SET parse, through ctnl_timeout_parse_policy()
 * against the L4 policy that CTA_TIMEOUT_L4PROTO picks.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

/*
 * All five callbacks carry cttimeout_nla_policy, so one attribute table
 * serves them.  DEFAULT_SET needs L4PROTO and DATA and DEFAULT_GET L3PROTO
 * and L4PROTO; neither reads a NAME, because they act on the netns's
 * default timeouts for the protocol, not on a timeout object.
 */
static const struct nfnl_cmd_grammar cttimeout_cmds[] = {
	{ IPCTNL_MSG_TIMEOUT_NEW,         "IPCTNL_MSG_TIMEOUT_NEW" },
	{ IPCTNL_MSG_TIMEOUT_GET,         "IPCTNL_MSG_TIMEOUT_GET" },
	{ IPCTNL_MSG_TIMEOUT_DELETE,      "IPCTNL_MSG_TIMEOUT_DELETE" },
	{ IPCTNL_MSG_TIMEOUT_DEFAULT_SET, "IPCTNL_MSG_TIMEOUT_DEFAULT_SET" },
	{ IPCTNL_MSG_TIMEOUT_DEFAULT_GET, "IPCTNL_MSG_TIMEOUT_DEFAULT_GET" },
};

/*
 * The per-L4 ids reuse the outer ones (CTA_TIMEOUT_TCP_SYN_SENT and
 * CTA_TIMEOUT_NAME are both 1), so one flat table holds both and the emitter
 * picks by position.
 */
static const struct nla_attr_spec cttimeout_attrs[] = {
	/* Command level (nfnetlink_cttimeout.c). */
	{ CTA_TIMEOUT_NAME,                  NLA_KIND_STRING,
					     CTNL_TIMEOUT_NAME_MAX - 1 },
	{ CTA_TIMEOUT_L3PROTO,               NLA_KIND_U16,    2 },
	{ CTA_TIMEOUT_L4PROTO,               NLA_KIND_U8,     1 },
	{ CTA_TIMEOUT_DATA,                  NLA_KIND_NESTED, 0 },

	/* Nested CTA_TIMEOUT_DATA payload — GENERIC arm
	 * (nf_conntrack_proto_generic.c generic_timeout_nla_policy). */
	{ CTA_TIMEOUT_GENERIC_TIMEOUT,       NLA_KIND_U32,    4 },

	/* TCP arm (nf_conntrack_proto_tcp.c tcp_timeout_nla_policy). */
	{ CTA_TIMEOUT_TCP_SYN_SENT,          NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_TCP_SYN_RECV,          NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_TCP_ESTABLISHED,       NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_TCP_FIN_WAIT,          NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_TCP_CLOSE_WAIT,        NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_TCP_LAST_ACK,          NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_TCP_TIME_WAIT,         NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_TCP_CLOSE,             NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_TCP_SYN_SENT2,         NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_TCP_RETRANS,           NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_TCP_UNACK,             NLA_KIND_U32,    4 },

	/* UDP arm (nf_conntrack_proto_udp.c udp_timeout_nla_policy). */
	{ CTA_TIMEOUT_UDP_UNREPLIED,         NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_UDP_REPLIED,           NLA_KIND_U32,    4 },

	/* ICMP arm (nf_conntrack_proto_icmp.c icmp_timeout_nla_policy). */
	{ CTA_TIMEOUT_ICMP_TIMEOUT,          NLA_KIND_U32,    4 },

	/* DCCP ids: the uapi header still defines them, but a kernel
	 * without the DCCP tracker answers an L4PROTO of IPPROTO_DCCP
	 * with -EOPNOTSUPP before parsing any of these. */
	{ CTA_TIMEOUT_DCCP_REQUEST,          NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_DCCP_RESPOND,          NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_DCCP_PARTOPEN,         NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_DCCP_OPEN,             NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_DCCP_CLOSEREQ,         NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_DCCP_CLOSING,          NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_DCCP_TIMEWAIT,         NLA_KIND_U32,    4 },

	/* SCTP arm (nf_conntrack_proto_sctp.c sctp_timeout_nla_policy).
	 * HEARTBEAT_ACKED is still validated by the kernel policy even
	 * though the state slot is no longer consumed. */
	{ CTA_TIMEOUT_SCTP_CLOSED,           NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_SCTP_COOKIE_WAIT,      NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_SCTP_COOKIE_ECHOED,    NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_SCTP_ESTABLISHED,      NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_SCTP_SHUTDOWN_SENT,    NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_SCTP_SHUTDOWN_RECD,    NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_SCTP_SHUTDOWN_ACK_SENT, NLA_KIND_U32,   4 },
	{ CTA_TIMEOUT_SCTP_HEARTBEAT_SENT,   NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_SCTP_HEARTBEAT_ACKED,  NLA_KIND_U32,    4 },

	/* GRE arm (nf_conntrack_proto_gre.c gre_timeout_nla_policy). */
	{ CTA_TIMEOUT_GRE_UNREPLIED,         NLA_KIND_U32,    4 },
	{ CTA_TIMEOUT_GRE_REPLIED,           NLA_KIND_U32,    4 },
};

struct nfnl_subsys_grammar sub_cttimeout = {
	.name = "cttimeout",
	.subsys_id = NFNL_SUBSYS_CTNETLINK_TIMEOUT,
	.cmds = cttimeout_cmds,
	.n_cmds = ARRAY_SIZE(cttimeout_cmds),
	.attrs = cttimeout_attrs,
	.n_attrs = ARRAY_SIZE(cttimeout_attrs),
};
