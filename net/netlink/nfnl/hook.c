/*
 * NETLINK_NETFILTER subsystem grammar: hook (NFNL_SUBSYS_HOOK), targeting
 * net/netfilter/nfnetlink_hook.c.  GET needs NFNLA_HOOK_HOOKNUM and serves
 * only NLM_F_DUMP (anything else is -EOPNOTSUPP); NFNLA_HOOK_DEV is read only
 * for NFPROTO_NETDEV.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_hook.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar hook_cmds[] = {
	{ NFNL_MSG_HOOK_GET, "NFNL_MSG_HOOK_GET" },
};

/*
 * The request path reads only HOOKNUM and DEV; PRIORITY, FUNCTION_NAME and
 * MODULE_NAME are reply-only (nfnl_hook_dump_one()) and never read by the
 * handler.  HOOKNUM is NLA_POLICY_MAX(NLA_BE32, 255) in the policy; the hook
 * arrays behind it hold NF_INET_NUMHOOKS entries or fewer, so most of that
 * range is refused one level down, in nfnl_hook_entries_head().
 */
static const struct nla_attr_spec hook_attrs[] = {
	{ NFNLA_HOOK_HOOKNUM,		NLA_KIND_BE32_MAX, 255 },
	{ NFNLA_HOOK_PRIORITY,		NLA_KIND_U32,    4 },
	{ NFNLA_HOOK_DEV,		NLA_KIND_STRING, 15 },
	{ NFNLA_HOOK_FUNCTION_NAME,	NLA_KIND_STRING, 127 },
	{ NFNLA_HOOK_MODULE_NAME,	NLA_KIND_STRING, 63 },
};

struct nfnl_subsys_grammar sub_hook = {
	.name = "hook",
	.subsys_id = NFNL_SUBSYS_HOOK,
	.cmds = hook_cmds,
	.n_cmds = ARRAY_SIZE(hook_cmds),
	.attrs = hook_attrs,
	.n_attrs = ARRAY_SIZE(hook_attrs),
};
