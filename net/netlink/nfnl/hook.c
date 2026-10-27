/*
 * NETLINK_NETFILTER subsystem grammar: hook (NFNL_SUBSYS_HOOK), targeting
 * net/netfilter/nfnetlink_hook.c.  GET needs NFNLA_HOOK_HOOKNUM and serves
 * only NLM_F_DUMP (anything else is -EOPNOTSUPP); NFNLA_HOOK_DEV is read only
 * for NFPROTO_NETDEV.
 */

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_hook.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

/*
 * HOOKNUM is NLA_POLICY_MAX(NLA_BE32, 255) in the policy, but the hook arrays
 * behind it are shorter, and nfnl_hook_entries_head() answers a number past
 * one -EINVAL.  IPv4, IPv6 and bridge, the families the body generator names
 * that it knows, hold NF_INET_NUMHOOKS entries; ARP and netdev hold fewer.
 * So the grammar draws the inet hooks; the numbers from there up to 255,
 * which only that refusal answers, go undrawn.
 */
static const unsigned int hook_hooknums[] = {
	NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD,
	NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING,
};

/*
 * The request path reads only HOOKNUM and DEV; PRIORITY, FUNCTION_NAME and
 * MODULE_NAME are reply-only (nfnl_hook_dump_one()) and never read by the
 * handler, so GET's table does not hold them.  nfnl_hook_get() answers
 * -EINVAL without HOOKNUM, which is marked .required; DEV is not, since only
 * a NFPROTO_NETDEV request reads it.
 */
static const struct nla_attr_spec hook_get_attrs[] = {
	{ NFNLA_HOOK_HOOKNUM,		NLA_KIND_BE32_ONEOF, 0, 0,
	  .oneof = hook_hooknums, .n_oneof = ARRAY_SIZE(hook_hooknums),
	  .required = true },
	{ NFNLA_HOOK_DEV,		NLA_KIND_STRING, 15 },
};

static const struct nfnl_cmd_grammar hook_cmds[] = {
	{ NFNL_MSG_HOOK_GET, "NFNL_MSG_HOOK_GET", false,
	  hook_get_attrs, ARRAY_SIZE(hook_get_attrs) },
};

struct nfnl_subsys_grammar sub_hook = {
	.name = "hook",
	.subsys_id = NFNL_SUBSYS_HOOK,
	.cmds = hook_cmds,
	.n_cmds = ARRAY_SIZE(hook_cmds),
};
