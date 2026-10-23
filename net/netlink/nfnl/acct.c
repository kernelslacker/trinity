/*
 * NETLINK_NETFILTER subsystem grammar: nfacct (NFNL_SUBSYS_ACCT), targeting
 * net/netfilter/nfnetlink_acct.c.  NEW and a non-dump GET need NFACCT_NAME;
 * only a GET with NLM_F_DUMP parses the NFACCT_FILTER nest
 * (nfnl_acct_start()).
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_acct.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

/*
 * Not listed: GET_CTRZERO, which zeroes the counters it reports, and
 * OVERQUOTA, a kernel event whose cb slot has no .call (nfnetlink_rcv_msg()
 * answers it -EINVAL).
 */
static const struct nfnl_cmd_grammar acct_cmds[] = {
	{ NFNL_MSG_ACCT_NEW, "NFNL_MSG_ACCT_NEW" },
	{ NFNL_MSG_ACCT_GET, "NFNL_MSG_ACCT_GET" },
	{ NFNL_MSG_ACCT_DEL, "NFNL_MSG_ACCT_DEL" },
};

/*
 * NFACCT_USE (emitted only) and NFACCT_PAD (64-bit alignment padding) have no
 * policy entry and are left out.
 */
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
