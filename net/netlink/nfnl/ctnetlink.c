/*
 * NETLINK_NETFILTER subsystem grammar: ctnetlink (NFNL_SUBSYS_CTNETLINK and
 * NFNL_SUBSYS_CTNETLINK_EXP), targeting net/netfilter/nf_conntrack_netlink.c.
 * The two subsystems validate against separate policies (ct_nla_policy with
 * CTA_*, exp_nla_policy with CTA_EXPECT_*), so each has its own attr table.
 */

#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

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
 * CTA_* attr spec table for NFNL_SUBSYS_CTNETLINK (conntrack entries).
 * Mirrors the kernel's ct_nla_policy entries the entry dispatchers gate
 * on.  Lengths follow the kernel's nla_policy maximums.  The nests are bare
 * NLA_NESTED there (max_len 0 here); the handlers parse them against
 * tuple_nla_policy, help_nla_policy, protoinfo_policy and the like.
 * CTA_TIMESTAMP_EVENT is left out: ct_nla_policy marks it NLA_REJECT, so the
 * four commands that carry that policy answer a message with it -EINVAL
 * before the handler runs.
 */
static const struct nla_attr_spec ctnetlink_attrs[] = {
	{ CTA_TUPLE_ORIG,     NLA_KIND_NESTED, 0 },
	{ CTA_TUPLE_REPLY,    NLA_KIND_NESTED, 0 },
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
	{ CTA_TUPLE_MASTER,   NLA_KIND_NESTED, 0 },
	{ CTA_SEQ_ADJ_ORIG,   NLA_KIND_NESTED, 0 },
	{ CTA_SEQ_ADJ_REPLY,  NLA_KIND_NESTED, 0 },
	{ CTA_ZONE,           NLA_KIND_U16,    2 },
	{ CTA_TIMESTAMP,      NLA_KIND_NESTED, 0 },
	{ CTA_LABELS,         NLA_KIND_BINARY, 16 },
	{ CTA_LABELS_MASK,    NLA_KIND_BINARY, 16 },
	{ CTA_SYNPROXY,       NLA_KIND_NESTED, 0 },
	{ CTA_FILTER,         NLA_KIND_NESTED, 0 },
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
	{ CTA_EXPECT_MASTER,    NLA_KIND_NESTED, 0  },
	{ CTA_EXPECT_TUPLE,     NLA_KIND_NESTED, 0  },
	{ CTA_EXPECT_MASK,      NLA_KIND_NESTED, 0  },
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

struct nfnl_subsys_grammar sub_ctnetlink = {
	.name = "ctnetlink",
	.subsys_id = NFNL_SUBSYS_CTNETLINK,
	.cmds = ctnetlink_cmds,
	.n_cmds = ARRAY_SIZE(ctnetlink_cmds),
	.attrs = ctnetlink_attrs,
	.n_attrs = ARRAY_SIZE(ctnetlink_attrs),
};

struct nfnl_subsys_grammar sub_ctnetlink_exp = {
	.name = "ctnetlink_exp",
	.subsys_id = NFNL_SUBSYS_CTNETLINK_EXP,
	.cmds = ctnetlink_exp_cmds,
	.n_cmds = ARRAY_SIZE(ctnetlink_exp_cmds),
	.attrs = ctnetlink_exp_attrs,
	.n_attrs = ARRAY_SIZE(ctnetlink_exp_attrs),
};
