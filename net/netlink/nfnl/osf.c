/*
 * NETLINK_NETFILTER subsystem grammar: osf (NFNL_SUBSYS_OSF), targeting
 * net/netfilter/nfnetlink_osf.c.  OSF_ATTR_FINGER is NLA_POLICY_EXACT_LEN of
 * a struct nf_osf_user_finger that the handlers use in place.  Both commands
 * demand capable(CAP_NET_ADMIN) in the initial user namespace, and ADD also
 * needs NLM_F_CREATE.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_osf.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar osf_cmds[] = {
	{ OSF_MSG_ADD,    "OSF_MSG_ADD" },
	{ OSF_MSG_REMOVE, "OSF_MSG_REMOVE" },
};

/*
 * EXACT_LEN rejects every other length, so min == max pins BINARY_FIXED2 to
 * sizeof(struct nf_osf_user_finger).
 */
static const struct nla_attr_spec osf_attrs[] = {
	{ OSF_ATTR_FINGER, NLA_KIND_BINARY_FIXED2,
	  sizeof(struct nf_osf_user_finger),
	  sizeof(struct nf_osf_user_finger) },
};

struct nfnl_subsys_grammar sub_osf = {
	.name = "osf",
	.subsys_id = NFNL_SUBSYS_OSF,
	.cmds = osf_cmds,
	.n_cmds = ARRAY_SIZE(osf_cmds),
	.attrs = osf_attrs,
	.n_attrs = ARRAY_SIZE(osf_attrs),
};
