/*
 * NETLINK_NETFILTER subsystem grammar: cttimeout
 * (NFNL_SUBSYS_CTNETLINK_TIMEOUT).
 *
 * nfnetlink_cttimeout is the userspace control plane for the
 * conntrack timeout-policy table — it lets userspace create/look-up/
 * delete named L4 timeout policies that can then be attached to flows
 * via the xt_CT target.  Lives in net/netfilter/nfnetlink_cttimeout.c,
 * gated by CONFIG_NF_CT_NETLINK_TIMEOUT=m.  The subsys is registered
 * with nfnetlink_subsystem_register() under subsys_id
 * NFNL_SUBSYS_CTNETLINK_TIMEOUT (8), so messages route through the
 * standard nfnetlink dispatcher — no genl family resolution to do.
 *
 * Without this grammar, Trinity's nfnetlink generator emitted the
 * cttimeout subsys byte paired with a random cmd + empty/garbage
 * payload, so the per-cmd validate gate inside nfnetlink_cttimeout.c
 * short-circuited on missing-attribute errors (NEW requires
 * CTA_TIMEOUT_NAME + CTA_TIMEOUT_L3PROTO + CTA_TIMEOUT_L4PROTO +
 * CTA_TIMEOUT_DATA; GET/DELETE gate on CTA_TIMEOUT_NAME) before
 * reaching the per-L4 nested parsers.
 *
 * Command set: the three user-facing commands the dispatcher accepts
 * (NEW / GET / DELETE) per the cttimeout_nfnl_cb[] callback table.
 * IPCTNL_MSG_TIMEOUT_DEFAULT_SET / DEFAULT_GET need a registered L4
 * timeout policy and parse against a different attr set, so a fuzzer
 * pointed at them from cold just bounces at the policy-resolution
 * gate; skip them here.  All three commands need CAP_NET_ADMIN and
 * will EPERM in unprivileged children, but the per-attr validate gate
 * runs before the perm check so the policy path gets exercised either
 * way.
 *
 * Attribute set: the four command-level attributes cttimeout_nla_policy[]
 * accepts, followed by the per-L4 CTA_TIMEOUT_<PROTO>_* namespaces that
 * the kernel walks under CTA_TIMEOUT_DATA:
 *   CTA_TIMEOUT_NAME    NLA_NUL_STRING, len = CTNL_TIMEOUT_NAME_MAX-1
 *   CTA_TIMEOUT_L3PROTO NLA_U16 (kernel reads as be16 via ntohs)
 *   CTA_TIMEOUT_L4PROTO NLA_U8
 *   CTA_TIMEOUT_DATA    NLA_NESTED (per-L4 sub-policy dispatched by
 *                       L4PROTO; children are picked from the same
 *                       flat table below).
 *
 * The per-L4 arms — GENERIC / TCP / UDP / ICMP / DCCP / SCTP / GRE —
 * live in disjoint enums (ctattr_timeout_tcp, ctattr_timeout_udp, ...)
 * and each carries NLA_U32 state-timeout values that the L4 policy
 * validators (tcp_timeout_nla_policy, udp_timeout_nla_policy, ...) gate
 * with .type = NLA_U32.  The kernel reads the payload as be32 via
 * nla_get_be32, but the on-wire length validator is 4 bytes, which is
 * what NLA_KIND_U32 emits.
 *
 * The per-L4 id numbering collides with the outer namespace
 * (CTA_TIMEOUT_TCP_SYN_SENT = 1 shares an id with CTA_TIMEOUT_NAME = 1;
 * CTA_TIMEOUT_UDP_UNREPLIED = 1 shares it too), because the kernel
 * matches every child against the policy of whichever nest is being
 * parsed.  The spec-driven emitter picks entries by index rather than
 * by id, so outer and inner definitions coexist in one flat table —
 * the same pattern net/netlink/nfnl/ipset.c and net/netlink/genl/
 * macsec.c already use for their outer + per-nest attr namespaces.
 *
 * All of the per-L4 arm constants below have been in the uapi header
 * since Linux 4.11 (and most since 3.7), so no #ifndef shims are
 * needed — the oldest build host trinity targets ships a newer uapi
 * than that.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar cttimeout_cmds[] = {
	{ IPCTNL_MSG_TIMEOUT_NEW,    "IPCTNL_MSG_TIMEOUT_NEW" },
	{ IPCTNL_MSG_TIMEOUT_GET,    "IPCTNL_MSG_TIMEOUT_GET" },
	{ IPCTNL_MSG_TIMEOUT_DELETE, "IPCTNL_MSG_TIMEOUT_DELETE" },
};

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

	/* DCCP arm (nf_conntrack_proto_dccp.c dccp_timeout_nla_policy). */
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
