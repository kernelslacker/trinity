/*
 * NETLINK_NETFILTER subsystem grammar: cttimeout
 * (NFNL_SUBSYS_CTNETLINK_TIMEOUT).
 *
 * nfnetlink_cttimeout is the userspace control plane for the
 * conntrack timeout-policy table — it lets userspace create/look-up/
 * delete named L4 timeout policies that can then be attached to flows
 * via the xt_CT target.  Lives in net/netfilter/nfnetlink_cttimeout.c,
 * gated by CONFIG_NF_CT_NETLINK_TIMEOUT=m.  The subsys is registered
 * with nfnetlink_subsystem_register() under subsys_id
 * NFNL_SUBSYS_CTNETLINK_TIMEOUT (8), so messages route through the
 * standard nfnetlink dispatcher — no genl family resolution to do.
 *
 * Without this grammar, Trinity's nfnetlink generator emitted the
 * cttimeout subsys byte paired with a random cmd + empty/garbage
 * payload, so the per-cmd validate gate inside nfnetlink_cttimeout.c
 * short-circuited on missing-attribute errors (NEW requires
 * CTA_TIMEOUT_NAME + CTA_TIMEOUT_L3PROTO + CTA_TIMEOUT_L4PROTO +
 * CTA_TIMEOUT_DATA; GET/DELETE gate on CTA_TIMEOUT_NAME) before
 * reaching the per-L4 nested parsers.
 *
 * Command set: the three user-facing commands the dispatcher accepts
 * (NEW / GET / DELETE) per the cttimeout_nfnl_cb[] callback table.
 * IPCTNL_MSG_TIMEOUT_DEFAULT_SET / DEFAULT_GET need a registered L4
 * timeout policy and parse against a different attr set, so a fuzzer
 * pointed at them from cold just bounces at the policy-resolution
 * gate; skip them here.  All three commands need CAP_NET_ADMIN and
 * will EPERM in unprivileged children, but the per-attr validate gate
 * runs before the perm check so the policy path gets exercised either
 * way.
 *
 * Attribute set: the four attributes cttimeout_nla_policy[] accepts —
 *   CTA_TIMEOUT_NAME    NLA_NUL_STRING, len = CTNL_TIMEOUT_NAME_MAX-1
 *   CTA_TIMEOUT_L3PROTO NLA_U16 (kernel reads as be16 via ntohs)
 *   CTA_TIMEOUT_L4PROTO NLA_U8
 *   CTA_TIMEOUT_DATA    NLA_NESTED (per-L4 sub-policy dispatched by
 *                       L4PROTO; length-only here so the nested parser
 *                       bounds checks get exercised, a follow-up
 *                       grammar can describe the inner sub-policies
 *                       once the generator gains per-attr nested-spec
 *                       dispatch).
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar cttimeout_cmds[] = {
	{ IPCTNL_MSG_TIMEOUT_NEW,    "IPCTNL_MSG_TIMEOUT_NEW" },
	{ IPCTNL_MSG_TIMEOUT_GET,    "IPCTNL_MSG_TIMEOUT_GET" },
	{ IPCTNL_MSG_TIMEOUT_DELETE, "IPCTNL_MSG_TIMEOUT_DELETE" },
};

static const struct nla_attr_spec cttimeout_attrs[] = {
	{ CTA_TIMEOUT_NAME,    NLA_KIND_STRING, CTNL_TIMEOUT_NAME_MAX - 1 },
	{ CTA_TIMEOUT_L3PROTO, NLA_KIND_U16,    2 },
	{ CTA_TIMEOUT_L4PROTO, NLA_KIND_U8,     1 },
	{ CTA_TIMEOUT_DATA,    NLA_KIND_NESTED, 0 },
};

struct nfnl_subsys_grammar sub_cttimeout = {
	.name = "cttimeout",
	.subsys_id = NFNL_SUBSYS_CTNETLINK_TIMEOUT,
	.cmds = cttimeout_cmds,
	.n_cmds = ARRAY_SIZE(cttimeout_cmds),
	.attrs = cttimeout_attrs,
	.n_attrs = ARRAY_SIZE(cttimeout_attrs),
};
