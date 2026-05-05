/*
 * NETLINK_NETFILTER subsystem grammar: ctnetlink (NFNL_SUBSYS_CTNETLINK
 * + NFNL_SUBSYS_CTNETLINK_EXP).
 *
 * ctnetlink exposes the conntrack table to userspace via two parallel
 * subsystems: NFNL_SUBSYS_CTNETLINK carries IPCTNL_MSG_CT_* (entries
 * + per-cpu/global stats) and NFNL_SUBSYS_CTNETLINK_EXP carries
 * IPCTNL_MSG_EXP_* (expectation table).  Both subsys IDs share the
 * CTA_* attribute namespace at command level — the kernel's
 * nf_conntrack_netlink.c registers a separate nfnl_callback table
 * per subsys but the per-attr nla_policy entries the dispatchers
 * gate on come from the same CTA_* enum.  We register both subsys
 * IDs against the shared cmd + attr tables so the lookup helper
 * returns the same grammar regardless of which side the type picker
 * landed on.
 *
 * Command set: read-side variants (GET / GET_STATS / GET_DYING /
 * GET_UNCONFIRMED on CT, GET / GET_STATS on EXP) plus their write-side
 * counterparts (NEW / DELETE).  The write-side commands need
 * CAP_NET_ADMIN in the original netns and will EPERM in unprivileged
 * children, but the dispatcher still runs the per-attr validate gate
 * before the perm check — so the attr policy paths get exercised
 * either way.
 *
 * Attribute set: a curated subset of the CTA_* namespace the kernel's
 * ctnetlink_get_conntrack() / ctnetlink_change_conntrack() walk in
 * the common cases.  TUPLE_* and PROTOINFO are NESTED — payload zero
 * and lengths are randomized by the spec-driven generator, exercising
 * the nested parser's bounds checks rather than the inner per-tuple
 * fields (those need a separate nested grammar table to do well).
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

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
 * Shared CTA_* attr spec table.  Each subsys's nla_policy slices a
 * different subset out of this namespace; emitting the union is
 * harmless — unknown-attr entries either get NLA_POLICY_UNSPEC'd
 * (accepted, validated by hand) or rejected with -EINVAL.  Either
 * branch exercises real parser code paths.
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
	.attrs = ctnetlink_attrs,
	.n_attrs = ARRAY_SIZE(ctnetlink_attrs),
};
