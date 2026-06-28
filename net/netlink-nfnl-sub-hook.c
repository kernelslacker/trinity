/*
 * NETLINK_NETFILTER subsystem grammar: hook (NFNL_SUBSYS_HOOK).
 *
 * nfnetlink_hook is the read-only introspection surface for the live
 * netfilter hook chain: userspace dumps the per-(family, hooknum)
 * list of registered hook functions so iptables/nft/etc. can show
 * who's wired into PREROUTING, INPUT, etc. and at what priority.
 * Lives in net/netfilter/nfnetlink_hook.c, gated by
 * CONFIG_NETFILTER_NETLINK_HOOK.  The subsys is registered with
 * nfnetlink_subsystem_register() under subsys_id NFNL_SUBSYS_HOOK (12),
 * so messages route through the standard nfnetlink dispatcher — no
 * genl family resolution to do.
 *
 * Without this grammar, Trinity's nfnetlink generator emitted a
 * random nfgenmsg body and a random cmd byte; the per-subsys
 * nfnl_callback dispatcher rejected almost every message at the
 * cmd-validate gate (the subsys exposes exactly one cmd) so the
 * dump path and its policy-validate gate never ran.
 *
 * Command set: a single user-facing command (GET) per the
 * nfnl_hook_cb[] callback table; the kernel exposes no NEW/DEL —
 * this subsys is read-only metadata.  GET goes through the dump
 * path; the policy-validate gate runs against nfnl_hook_dump_policy
 * before the dump iterator walks the per-family hook arrays.
 *
 * Attribute set: NFNLA_HOOK_* from nfnetlink_hook.h.  The dump
 * policy only constrains NFNLA_HOOK_HOOKNUM (NLA_U32) and
 * NFNLA_HOOK_DEV (NLA_STRING, .len = IFNAMSIZ - 1 = 15) — those two
 * are what the iterator filters on.  The remaining leaf attrs
 * (PRIORITY, FUNCTION_NAME, MODULE_NAME) are reply-only in
 * nfnl_hook_dump_one(), but emitting them on the request side keeps
 * the policy/attr-parsing path under fuzz pressure for the case
 * where future kernels widen the input policy or add a strict-mode
 * unknown-attr reject.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_hook.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar hook_cmds[] = {
	{ NFNL_MSG_HOOK_GET, "NFNL_MSG_HOOK_GET" },
};

static const struct nla_attr_spec hook_attrs[] = {
	{ NFNLA_HOOK_HOOKNUM,		NLA_KIND_U32,    4 },
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
