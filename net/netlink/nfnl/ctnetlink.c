/*
 * NETLINK_NETFILTER subsystem grammar: ctnetlink (NFNL_SUBSYS_CTNETLINK
 * + NFNL_SUBSYS_CTNETLINK_EXP).
 *
 * ctnetlink exposes the conntrack table to userspace via two parallel
 * subsystems: NFNL_SUBSYS_CTNETLINK carries IPCTNL_MSG_CT_* (entries
 * + per-cpu/global stats) and NFNL_SUBSYS_CTNETLINK_EXP carries
 * IPCTNL_MSG_EXP_* (expectation table).  The two sides do NOT share an
 * attribute namespace: nf_conntrack_netlink.c validates CT commands
 * against ct_nla_policy (CTA_*) and EXP commands against
 * exp_nla_policy (CTA_EXPECT_*).  Each subsys needs its own attr table
 * here, otherwise EXP commands get length-rejected on the CTA_* policy
 * before the expectation-table handler ever runs.
 *
 * Command set: read-side variants (GET / GET_STATS / GET_DYING /
 * GET_UNCONFIRMED on CT, GET / GET_STATS on EXP) plus their write-side
 * counterparts (NEW / DELETE).  The write-side commands need
 * CAP_NET_ADMIN in the original netns and will EPERM in unprivileged
 * children, but the dispatcher still runs the per-attr validate gate
 * before the perm check — so the attr policy paths get exercised
 * either way.
 *
 * Attribute set: a curated subset of each namespace the kernel's
 * dispatchers walk in the common cases.  TUPLE_* / MASTER / MASK and
 * PROTOINFO are NESTED — payload zero and lengths are randomized by
 * the spec-driven generator, exercising the nested parser's bounds
 * checks rather than the inner per-tuple fields (those need a separate
 * nested grammar table to do well).
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

/*
 * Fresh-uapi shims for CTA_* ids that build hosts with a stale
 * <linux/netfilter/nfnetlink_conntrack.h> may not yet know.  Values
 * mirror the mainline enum ctattr_type ordering; SECMARK is retained
 * as an obsolete-but-parsed scalar the kernel still validates.
 */
#ifndef CTA_SECMARK
#define CTA_SECMARK        17
#endif
#ifndef CTA_SECCTX
#define CTA_SECCTX         19
#endif
#ifndef CTA_TIMESTAMP_EVENT
#define CTA_TIMESTAMP_EVENT 27
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
 * on.  Lengths follow the kernel's nla_policy maximums; nested entries
 * carry max_len 0 so the generator emits a header + randomized inner
 * payload that the nested parser then walks.
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
	{ CTA_TIMESTAMP_EVENT, NLA_KIND_NESTED, 0 },
};

/*
 * CTA_EXPECT_* attr spec table for NFNL_SUBSYS_CTNETLINK_EXP.  Mirrors
 * exp_nla_policy in nf_conntrack_netlink.c.  CTA_EXPECT_HELP_NAME and
 * CTA_EXPECT_FN are NUL-terminated strings bounded by the kernel-side
 * NF_CT_HELPER_NAME_LEN (16) / 32 respectively; the spec records the
 * non-terminator max.
 */
static const struct nla_attr_spec ctnetlink_exp_attrs[] = {
	{ CTA_EXPECT_MASTER,    NLA_KIND_NESTED, 0  },
	{ CTA_EXPECT_TUPLE,     NLA_KIND_NESTED, 0  },
	{ CTA_EXPECT_MASK,      NLA_KIND_NESTED, 0  },
	{ CTA_EXPECT_TIMEOUT,   NLA_KIND_U32,    4  },
	{ CTA_EXPECT_ID,        NLA_KIND_U32,    4  },
	{ CTA_EXPECT_HELP_NAME, NLA_KIND_STRING, 15 },
	{ CTA_EXPECT_ZONE,      NLA_KIND_U32,    4  },
	{ CTA_EXPECT_FLAGS,     NLA_KIND_U32,    4  },
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
