/*
 * NETLINK_NETFILTER subsystem grammar: ctnetlink (NFNL_SUBSYS_CTNETLINK and
 * NFNL_SUBSYS_CTNETLINK_EXP), targeting net/netfilter/nf_conntrack_netlink.c.
 * The two subsystems validate against separate policies (ct_nla_policy with
 * CTA_*, exp_nla_policy with CTA_EXPECT_*), so each has its own attr table.
 */

#include <linux/netfilter.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

#include "kernel/nfnetlink_conntrack.h"

/*
 * Fresh-uapi shims for CTA_* ids that build hosts with a stale
 * <linux/netfilter/nfnetlink_conntrack.h> may not yet know.  Values
 * mirror the mainline enum ctattr_type ordering.  SECMARK is obsolete
 * and ct_nla_policy has no entry for it, so the kernel never validates
 * it.
 */
#ifndef CTA_SECMARK
#define CTA_SECMARK        17
#endif
#ifndef CTA_SECCTX
#define CTA_SECCTX         19
#endif

static const struct nfnl_cmd_grammar ctnetlink_cmds[] = {
	{ IPCTNL_MSG_CT_NEW,             "IPCTNL_MSG_CT_NEW" },
	{ IPCTNL_MSG_CT_GET,             "IPCTNL_MSG_CT_GET" },
	{ IPCTNL_MSG_CT_DELETE,          "IPCTNL_MSG_CT_DELETE" },
	{ IPCTNL_MSG_CT_GET_CTRZERO,     "IPCTNL_MSG_CT_GET_CTRZERO" },
	{ IPCTNL_MSG_CT_GET_STATS_CPU,   "IPCTNL_MSG_CT_GET_STATS_CPU" },
	{ IPCTNL_MSG_CT_GET_STATS,       "IPCTNL_MSG_CT_GET_STATS" },
	{ IPCTNL_MSG_CT_GET_DYING,       "IPCTNL_MSG_CT_GET_DYING" },
	{ IPCTNL_MSG_CT_GET_UNCONFIRMED, "IPCTNL_MSG_CT_GET_UNCONFIRMED" },
};

static const struct nfnl_cmd_grammar ctnetlink_exp_cmds[] = {
	{ IPCTNL_MSG_EXP_NEW,            "IPCTNL_MSG_EXP_NEW" },
	{ IPCTNL_MSG_EXP_GET,            "IPCTNL_MSG_EXP_GET" },
	{ IPCTNL_MSG_EXP_DELETE,         "IPCTNL_MSG_EXP_DELETE" },
	{ IPCTNL_MSG_EXP_GET_STATS_CPU,  "IPCTNL_MSG_EXP_GET_STATS_CPU" },
};

/*
 * The children of CTA_FILTER, from cta_filter_nla_policy, which
 * ctnetlink_parse_filter() applies with the strict nla_parse_nested(): an id
 * past CTA_FILTER_MAX, or a nest flag on a child, answers the request -EINVAL.
 * The two flags words are NLA_POLICY_MASK(NLA_U32, CTA_FILTER_F_ALL), in host
 * order, and CTA_FILTER_F_ALL (net/netfilter/nf_internals.h) is the twelve
 * bits that CTA_FILTER_F_CTA_IP_SRC to CTA_FILTER_F_CTA_PROTO_ICMPV6_ID
 * name.  CTA_FILTER_ZONE, added by 46da6029bf46, is a flag that
 * ctnetlink_alloc_filter() answers -EINVAL unless CTA_ZONE is there too.
 */
static const struct nla_attr_spec ctnetlink_filter_attrs[] = {
	{ CTA_FILTER_ORIG_FLAGS,  NLA_KIND_U32_MASK, 0xfff },
	{ CTA_FILTER_REPLY_FLAGS, NLA_KIND_U32_MASK, 0xfff },
	{ CTA_FILTER_ZONE,        NLA_KIND_FLAG,     0 },
};

/*
 * The tuple's children, from tuple_nla_policy, cta_ip_nla_policy and
 * proto_nla_policy in nf_conntrack_netlink.c: the IP nest holds the V4
 * pair, each a U32, or the V6 pair, each 16 bytes, and the PROTO nest
 * the number and the fields the L4 protocol reads, ports for TCP and
 * UDP and the type, code and id for ICMP and ICMPv6, each in its own
 * slot.  Which of them the handler wants its flags say, which no mark
 * can say of an attribute in another table.
 */
static const struct nla_attr_spec ctnetlink_tuple_ip_attrs[] = {
	{ CTA_IP_V4_SRC, NLA_KIND_U32,    4 },
	{ CTA_IP_V4_DST, NLA_KIND_U32,    4 },
	{ CTA_IP_V6_SRC, NLA_KIND_BINARY, 16 },
	{ CTA_IP_V6_DST, NLA_KIND_BINARY, 16 },
};

static const struct nla_attr_spec ctnetlink_tuple_proto_attrs[] = {
	{ CTA_PROTO_NUM,         NLA_KIND_U8,  1 },
	{ CTA_PROTO_SRC_PORT,    NLA_KIND_U16, 2 },
	{ CTA_PROTO_DST_PORT,    NLA_KIND_U16, 2 },
	{ CTA_PROTO_ICMP_ID,     NLA_KIND_U16, 2 },
	{ CTA_PROTO_ICMP_TYPE,   NLA_KIND_U8,  1 },
	{ CTA_PROTO_ICMP_CODE,   NLA_KIND_U8,  1 },
	{ CTA_PROTO_ICMPV6_ID,   NLA_KIND_U16, 2 },
	{ CTA_PROTO_ICMPV6_TYPE, NLA_KIND_U8,  1 },
	{ CTA_PROTO_ICMPV6_CODE, NLA_KIND_U8,  1 },
};

static const struct nla_attr_spec ctnetlink_tuple_attrs[] = {
	{ CTA_TUPLE_IP,    NLA_KIND_NESTED, 0, 0,
	  ctnetlink_tuple_ip_attrs, ARRAY_SIZE(ctnetlink_tuple_ip_attrs) },
	{ CTA_TUPLE_PROTO, NLA_KIND_NESTED, 0, 0,
	  ctnetlink_tuple_proto_attrs,
	  ARRAY_SIZE(ctnetlink_tuple_proto_attrs) },
	{ CTA_TUPLE_ZONE,  NLA_KIND_U16,    2 },
};

/*
 * CTA_* attr spec table for NFNL_SUBSYS_CTNETLINK (conntrack entries).
 * Mirrors the kernel's ct_nla_policy entries the entry dispatchers gate
 * on.  Lengths follow the kernel's nla_policy maximums.  The nests are bare
 * NLA_NESTED there (max_len 0 here); the handlers parse them against
 * tuple_nla_policy, help_nla_policy, protoinfo_policy and the like, except
 * CTA_FILTER, whose children have the table above, and the tuples, whose
 * children have the tables above.
 * CTA_TIMESTAMP_EVENT is left out: ct_nla_policy marks it NLA_REJECT, so the
 * four commands that carry that policy answer a message with it -EINVAL
 * before the handler runs.
 */
static const struct nla_attr_spec ctnetlink_attrs[] = {
	{ CTA_TUPLE_ORIG,     NLA_KIND_NESTED, 0, 0,
	  ctnetlink_tuple_attrs, ARRAY_SIZE(ctnetlink_tuple_attrs) },
	{ CTA_TUPLE_REPLY,    NLA_KIND_NESTED, 0, 0,
	  ctnetlink_tuple_attrs, ARRAY_SIZE(ctnetlink_tuple_attrs) },
	{ CTA_STATUS,         NLA_KIND_U32,    4 },
	{ CTA_PROTOINFO,      NLA_KIND_NESTED, 0 },
	{ CTA_HELP,           NLA_KIND_NESTED, 0 },
	{ CTA_NAT_SRC,        NLA_KIND_NESTED, 0 },
	{ CTA_NAT_DST,        NLA_KIND_NESTED, 0 },
	{ CTA_TIMEOUT,        NLA_KIND_U32,    4 },
	{ CTA_MARK,           NLA_KIND_U32,    4 },
	{ CTA_MARK_MASK,      NLA_KIND_U32,    4 },
	{ CTA_COUNTERS_ORIG,  NLA_KIND_NESTED, 0 },
	{ CTA_COUNTERS_REPLY, NLA_KIND_NESTED, 0 },
	{ CTA_USE,            NLA_KIND_U32,    4 },
	{ CTA_ID,             NLA_KIND_U32,    4 },
	{ CTA_TUPLE_MASTER,   NLA_KIND_NESTED, 0, 0,
	  ctnetlink_tuple_attrs, ARRAY_SIZE(ctnetlink_tuple_attrs) },
	{ CTA_SEQ_ADJ_ORIG,   NLA_KIND_NESTED, 0 },
	{ CTA_SEQ_ADJ_REPLY,  NLA_KIND_NESTED, 0 },
	{ CTA_ZONE,           NLA_KIND_U16,    2 },
	{ CTA_TIMESTAMP,      NLA_KIND_NESTED, 0 },
	{ CTA_LABELS,         NLA_KIND_BINARY, 16 },
	{ CTA_LABELS_MASK,    NLA_KIND_BINARY, 16 },
	{ CTA_SYNPROXY,       NLA_KIND_NESTED, 0 },
	{ CTA_FILTER,         NLA_KIND_NESTED, 0, 0,
	  ctnetlink_filter_attrs, ARRAY_SIZE(ctnetlink_filter_attrs) },
	{ CTA_STATUS_MASK,    NLA_KIND_U32,    4 },
	{ CTA_SECMARK,        NLA_KIND_U32,    4 },
	{ CTA_SECCTX,         NLA_KIND_NESTED, 0 },
};

/*
 * CTA_EXPECT_* attr spec table for NFNL_SUBSYS_CTNETLINK_EXP.  Mirrors
 * exp_nla_policy in nf_conntrack_netlink.c.  CTA_EXPECT_HELP_NAME and
 * CTA_EXPECT_FN are NUL-terminated strings; the kernel bounds only
 * CTA_EXPECT_HELP_NAME (NF_CT_HELPER_NAME_LEN - 1, the non-terminator
 * max the spec records), so the 31 on CTA_EXPECT_FN is the spec's own
 * size, not a policy limit.  CTA_EXPECT_FLAGS is NLA_POLICY_MASK with the
 * kernel's NF_CT_EXPECT_MASK, the three flags below.
 */
static const struct nla_attr_spec ctnetlink_exp_attrs[] = {
	{ CTA_EXPECT_MASTER,    NLA_KIND_NESTED, 0, 0,
	  ctnetlink_tuple_attrs, ARRAY_SIZE(ctnetlink_tuple_attrs) },
	{ CTA_EXPECT_TUPLE,     NLA_KIND_NESTED, 0, 0,
	  ctnetlink_tuple_attrs, ARRAY_SIZE(ctnetlink_tuple_attrs) },
	{ CTA_EXPECT_MASK,      NLA_KIND_NESTED, 0, 0,
	  ctnetlink_tuple_attrs, ARRAY_SIZE(ctnetlink_tuple_attrs) },
	{ CTA_EXPECT_TIMEOUT,   NLA_KIND_U32,    4  },
	{ CTA_EXPECT_ID,        NLA_KIND_U32,    4  },
	{ CTA_EXPECT_HELP_NAME, NLA_KIND_STRING, 15 },
	{ CTA_EXPECT_ZONE,      NLA_KIND_U32,    4  },
	{ CTA_EXPECT_FLAGS,     NLA_KIND_BE32_MASK,
				NF_CT_EXPECT_PERMANENT | NF_CT_EXPECT_INACTIVE |
				NF_CT_EXPECT_USERSPACE },
	{ CTA_EXPECT_CLASS,     NLA_KIND_U32,    4  },
	{ CTA_EXPECT_NAT,       NLA_KIND_NESTED, 0  },
	{ CTA_EXPECT_FN,        NLA_KIND_STRING, 31 },
};

/*
 * ctnetlink_parse_tuple() answers any family but IPv4 and IPv6
 * -EOPNOTSUPP before it looks at a tuple, in both subsystems.
 */
static const unsigned char ctnetlink_families[] = {
	NFPROTO_IPV4, NFPROTO_IPV6,
};

struct nfnl_subsys_grammar sub_ctnetlink = {
	.name = "ctnetlink",
	.subsys_id = NFNL_SUBSYS_CTNETLINK,
	.cmds = ctnetlink_cmds,
	.n_cmds = ARRAY_SIZE(ctnetlink_cmds),
	.attrs = ctnetlink_attrs,
	.n_attrs = ARRAY_SIZE(ctnetlink_attrs),
	.families = ctnetlink_families,
	.n_families = ARRAY_SIZE(ctnetlink_families),
};

struct nfnl_subsys_grammar sub_ctnetlink_exp = {
	.name = "ctnetlink_exp",
	.subsys_id = NFNL_SUBSYS_CTNETLINK_EXP,
	.cmds = ctnetlink_exp_cmds,
	.n_cmds = ARRAY_SIZE(ctnetlink_exp_cmds),
	.attrs = ctnetlink_exp_attrs,
	.n_attrs = ARRAY_SIZE(ctnetlink_exp_attrs),
	.families = ctnetlink_families,
	.n_families = ARRAY_SIZE(ctnetlink_families),
};
