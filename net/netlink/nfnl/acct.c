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
 * NEW, GET and DEL find an object by strncmp()ing its name, and NEW answers a
 * name it already has -EBUSY, so a command finds what NEW made only if it
 * carries the same string.  Every name is this one word, which the policy's
 * NLA_NUL_STRING of up to NFACCT_NAME_MAX - 1 characters takes; the draw in
 * eight that is random letters makes another object or misses.
 */
static const char acct_word[] = "trinity";

/*
 * NFACCT_USE (emitted only) and NFACCT_PAD (64-bit alignment padding) have no
 * policy entry and are left out.  nfnl_acct_policy masks NFACCT_FLAGS with
 * the kernel's NFACCT_F_QUOTA, the two quota bits; NEW then refuses a word
 * with both set.
 *
 * Each command has a table of its own, which marks .required what the handler
 * answers -EINVAL without.  NEW needs the name, which it also refuses empty,
 * and reads the counters, the flags and the quota.  GET needs the name unless
 * it is a dump, and a dump reads the NFACCT_FILTER nest, whose mask and value
 * nfnl_acct_start() both want.  DEL takes a name, and without one deletes
 * every object, so its name is not marked.
 */
static const struct nla_attr_spec acct_filter_attrs[] = {
	{ NFACCT_FILTER_MASK,  NLA_KIND_U32, 4, .required = true },
	{ NFACCT_FILTER_VALUE, NLA_KIND_U32, 4, .required = true },
};

static const struct nla_attr_spec acct_new_attrs[] = {
	{ NFACCT_NAME,   NLA_KIND_STRING_WORD, 0, 0, .word = acct_word,
			 .required = true },
	{ NFACCT_PKTS,   NLA_KIND_U64,    8 },
	{ NFACCT_BYTES,  NLA_KIND_U64,    8 },
	{ NFACCT_FLAGS,  NLA_KIND_BE32_MASK,
			 NFACCT_F_QUOTA_PKTS | NFACCT_F_QUOTA_BYTES },
	{ NFACCT_QUOTA,  NLA_KIND_U64,    8 },
};

static const struct nla_attr_spec acct_get_attrs[] = {
	{ NFACCT_NAME,   NLA_KIND_STRING_WORD, 0, 0, .word = acct_word,
			 .required = true },
	{ NFACCT_FILTER, NLA_KIND_NESTED, 0, 0,
			 acct_filter_attrs, ARRAY_SIZE(acct_filter_attrs) },
};

static const struct nla_attr_spec acct_del_attrs[] = {
	{ NFACCT_NAME,   NLA_KIND_STRING_WORD, 0, 0, .word = acct_word },
};

/*
 * Not listed: GET_CTRZERO, which zeroes the counters it reports, and
 * OVERQUOTA, a kernel event whose cb slot has no .call (nfnetlink_rcv_msg()
 * answers it -EINVAL).
 */
static const struct nfnl_cmd_grammar acct_cmds[] = {
	{ NFNL_MSG_ACCT_NEW, "NFNL_MSG_ACCT_NEW", false,
	  acct_new_attrs, ARRAY_SIZE(acct_new_attrs) },
	{ NFNL_MSG_ACCT_GET, "NFNL_MSG_ACCT_GET", false,
	  acct_get_attrs, ARRAY_SIZE(acct_get_attrs) },
	{ NFNL_MSG_ACCT_DEL, "NFNL_MSG_ACCT_DEL", false,
	  acct_del_attrs, ARRAY_SIZE(acct_del_attrs) },
};

struct nfnl_subsys_grammar sub_acct = {
	.name = "acct",
	.subsys_id = NFNL_SUBSYS_ACCT,
	.cmds = acct_cmds,
	.n_cmds = ARRAY_SIZE(acct_cmds),
};
