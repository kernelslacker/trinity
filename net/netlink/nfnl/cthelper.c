/*
 * NETLINK_NETFILTER subsystem grammar: cthelper (NFNL_SUBSYS_CTHELPER),
 * targeting net/netfilter/nfnetlink_cthelper.c.  NFCTH_TUPLE and NFCTH_POLICY
 * are untyped in nfnl_cthelper_policy and parsed by the handlers (POLICY is
 * a two-level nest), each of which first demands capable(CAP_NET_ADMIN) in
 * the initial user namespace.
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

/*
 * NFCTH_NAME is 15 = NF_CT_HELPER_NAME_LEN - 1, the policy cap; the 16 lives
 * in a kernel-internal header, not uapi.
 */
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
