/*
 * NETLINK_NETFILTER subsystem grammar: cthelper (NFNL_SUBSYS_CTHELPER).
 *
 * nfnetlink_cthelper is the userspace control plane for conntrack
 * helpers — it lets userspace register/query/delete connection
 * trackers (typically backed by a NFQUEUE handler) for L7 protocols
 * the kernel doesn't grok natively.  Lives in
 * net/netfilter/nfnetlink_cthelper.c, gated by
 * CONFIG_NF_CT_NETLINK_HELPER=m.  The subsys is registered with
 * nfnetlink_subsystem_register() under subsys_id NFNL_SUBSYS_CTHELPER
 * (9), so messages route through the standard nfnetlink dispatcher —
 * no genl family resolution to do.
 *
 * Without this grammar, Trinity's nfnetlink generator emitted a
 * random nfgenmsg body and never produced any NFCTH_* TLVs, so the
 * per-cmd validate gates inside nfnetlink_cthelper.c short-circuited
 * on missing-attribute errors (NEW requires NFCTH_NAME + NFCTH_TUPLE
 * + NFCTH_POLICY + NFCTH_PRIV_DATA_LEN; GET/DEL gate on NFCTH_NAME)
 * before reaching the nested-attr parsers.
 *
 * Command set: the three user-facing commands the dispatcher accepts
 * (NEW / GET / DEL) per the nfnl_cthelper_cb[] callback table.  All
 * three need CAP_NET_ADMIN and will EPERM in unprivileged children,
 * but the per-attr validate gate runs before the perm check so the
 * policy paths get exercised either way.
 *
 * Attribute set: NFCTH_* command-level namespace from
 * include/uapi/linux/netfilter/nfnetlink_cthelper.h.  Top-level
 * nfnl_cthelper_policy in net/netfilter/nfnetlink_cthelper.c gates:
 *   NFCTH_NAME          NLA_NUL_STRING, len = NF_CT_HELPER_NAME_LEN-1
 *   NFCTH_QUEUE_NUM     NLA_U32 (kernel reads as be32 via ntohl)
 *   NFCTH_PRIV_DATA_LEN NLA_U32 (likewise be32)
 *   NFCTH_STATUS        NLA_U32 (likewise be32)
 * NFCTH_TUPLE and NFCTH_POLICY are absent from the top-level policy —
 * the kernel hands their payloads straight to nla_parse_nested
 * against per-sub-attr policies (NFCTH_TUPLE → {L3PROTONUM u16,
 * L4PROTONUM u8}; NFCTH_POLICY → NFCTH_POLICY_SET_NUM u32 + up to 4
 * NFCTH_POLICY_SET[N] sub-nests each carrying {NFCTH_POLICY_NAME str,
 * NFCTH_POLICY_EXPECT_MAX u32, NFCTH_POLICY_EXPECT_TIMEOUT u32}).
 * That makes NFCTH_POLICY a genuine 2-level nest.  We register both
 * as length-only NESTED here so the nested-parser bounds checks
 * (nla_validate_nested at the immediate level) get exercised; a
 * follow-up grammar can describe the inner sub-policies once the
 * generator gains per-attr nested-spec dispatch.
 *
 * NF_CT_HELPER_NAME_LEN (16) lives in the kernel-internal header
 * include/net/netfilter/nf_conntrack_helper.h, not in uapi, so we
 * hardcode 15 (= NF_CT_HELPER_NAME_LEN - 1, the NUL-stripped policy
 * cap) here rather than invent a uapi symbol.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_cthelper.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar cthelper_cmds[] = {
	{ NFNL_MSG_CTHELPER_NEW, "NFNL_MSG_CTHELPER_NEW" },
	{ NFNL_MSG_CTHELPER_GET, "NFNL_MSG_CTHELPER_GET" },
	{ NFNL_MSG_CTHELPER_DEL, "NFNL_MSG_CTHELPER_DEL" },
};

static const struct nla_attr_spec cthelper_attrs[] = {
	{ NFCTH_NAME,          NLA_KIND_STRING, 15 },
	{ NFCTH_TUPLE,         NLA_KIND_NESTED, 0 },
	{ NFCTH_QUEUE_NUM,     NLA_KIND_U32,    4 },
	{ NFCTH_POLICY,        NLA_KIND_NESTED, 0 },
	{ NFCTH_PRIV_DATA_LEN, NLA_KIND_U32,    4 },
	{ NFCTH_STATUS,        NLA_KIND_U32,    4 },
};

struct nfnl_subsys_grammar sub_cthelper = {
	.name = "cthelper",
	.subsys_id = NFNL_SUBSYS_CTHELPER,
	.cmds = cthelper_cmds,
	.n_cmds = ARRAY_SIZE(cthelper_cmds),
	.attrs = cthelper_attrs,
	.n_attrs = ARRAY_SIZE(cthelper_attrs),
};
