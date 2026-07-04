/*
 * NETLINK_NETFILTER subsystem grammar: nfacct (NFNL_SUBSYS_ACCT).
 *
 * nfacct is the kernel's named byte/packet counter table used by the
 * xt_nfacct match and the per-counter quota events; it lives in
 * net/netfilter/nfnetlink_acct.c, gated by CONFIG_NETFILTER_NETLINK_ACCT.
 * The subsys is registered with nfnetlink_subsystem_register() under
 * subsys_id NFNL_SUBSYS_ACCT (7), so messages route through the standard
 * nfnetlink dispatcher — no genl family resolution to do.
 *
 * Without this grammar, Trinity's nfnetlink generator emitted a random
 * nfgenmsg body and never produced any NFACCT_* TLVs, so the per-cmd
 * validate gates inside nfnetlink_acct.c short-circuited on
 * missing-attribute errors (NFACCT_NAME is required by every user-facing
 * command) before reaching the parser.
 *
 * Command set: the three user-facing commands the dispatcher accepts
 * (NEW / GET / DEL) per the nfnl_acct_cb[] callback table.  NEW + DEL
 * need CAP_NET_ADMIN and will EPERM in unprivileged children, but the
 * per-attr validate gate runs before the perm check so the policy paths
 * get exercised either way.  NFNL_MSG_ACCT_GET_CTRZERO and
 * NFNL_MSG_ACCT_OVERQUOTA are deliberately omitted — the former is a
 * read-and-zero variant that would race other subsystems' counters under
 * fuzz, and the latter is a kernel→user multicast event with no callback
 * slot (the dispatcher -EOPNOTSUPP's it cleanly).
 *
 * Attribute set: NFACCT_* command-level namespace from
 * include/uapi/linux/netfilter/nfnetlink_acct.h, sized per nfnl_acct_policy
 * in net/netfilter/nfnetlink_acct.c.  NFACCT_NAME is NLA_NUL_STRING capped
 * at NFACCT_NAME_MAX-1 (=31); NFACCT_BYTES/PKTS/QUOTA are NLA_U64;
 * NFACCT_FLAGS is NLA_U32; NFACCT_FILTER is NLA_NESTED (inner
 * NFACCT_FILTER_MASK/VALUE u32 pair — left to a follow-up nested grammar;
 * the length-only NESTED header still walks the nested parser's bounds
 * checks).  NFACCT_USE and NFACCT_PAD are not in the input policy
 * (USE is kernel-emit-only, PAD is NLA_U64 padding) so they're omitted.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_acct.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar acct_cmds[] = {
	{ NFNL_MSG_ACCT_NEW, "NFNL_MSG_ACCT_NEW" },
	{ NFNL_MSG_ACCT_GET, "NFNL_MSG_ACCT_GET" },
	{ NFNL_MSG_ACCT_DEL, "NFNL_MSG_ACCT_DEL" },
};

static const struct nla_attr_spec acct_attrs[] = {
	{ NFACCT_NAME,   NLA_KIND_STRING, NFACCT_NAME_MAX - 1 },
	{ NFACCT_PKTS,   NLA_KIND_U64,    8 },
	{ NFACCT_BYTES,  NLA_KIND_U64,    8 },
	{ NFACCT_FLAGS,  NLA_KIND_U32,    4 },
	{ NFACCT_QUOTA,  NLA_KIND_U64,    8 },
	{ NFACCT_FILTER, NLA_KIND_NESTED, 0 },
};

struct nfnl_subsys_grammar sub_acct = {
	.name = "acct",
	.subsys_id = NFNL_SUBSYS_ACCT,
	.cmds = acct_cmds,
	.n_cmds = ARRAY_SIZE(acct_cmds),
	.attrs = acct_attrs,
	.n_attrs = ARRAY_SIZE(acct_attrs),
};
