/*
 * NETLINK_NETFILTER subsystem grammar: osf (NFNL_SUBSYS_OSF).
 *
 * nfnetlink_osf is the userspace control plane for the passive OS
 * fingerprint table consumed by the xt_osf match — it lets userspace
 * add/remove fingerprints (the pf-style "Linux 2.6.x" / "Windows XP"
 * signatures) against which incoming SYN packets are matched.  Lives
 * in net/netfilter/nfnetlink_osf.c, gated by
 * CONFIG_NETFILTER_NETLINK_OSF=m.  The subsys is registered with
 * nfnetlink_subsystem_register() under subsys_id NFNL_SUBSYS_OSF (5),
 * so messages route through the standard nfnetlink dispatcher — no
 * genl family resolution to do.
 *
 * Without this grammar, Trinity's nfnetlink generator emitted a
 * random nfgenmsg body and never produced an OSF_ATTR_FINGER TLV, so
 * the per-cmd validate gate inside nfnetlink_osf.c short-circuited on
 * missing-attribute errors (both ADD and REMOVE require
 * OSF_ATTR_FINGER and bail with -EINVAL before reaching the
 * fingerprint installer or the table walker).
 *
 * Command set: the two user-facing commands the dispatcher accepts
 * (ADD / REMOVE) per the nfnl_osf_callbacks[] table.  Both need
 * CAP_NET_ADMIN and will EPERM in unprivileged children, but the
 * per-attr validate gate runs before the perm check so the policy
 * path gets exercised either way.
 *
 * Attribute set: a single OSF_ATTR_FINGER carrying a fixed
 * struct nf_osf_user_finger blob.  The top-level nfnl_osf_policy in
 * net/netfilter/nfnetlink_osf.c gates it as NLA_UNSPEC with
 * .len = sizeof(struct nf_osf_user_finger), so any shorter payload
 * is rejected by nla_validate before the handler ever runs, and the
 * handler then casts nla_data() straight to a struct pointer and
 * reads exactly sizeof bytes.  NLA_KIND_BINARY's [4, max_len] sweep
 * would burn the bulk of emissions on guaranteed -EINVAL; pin both
 * ends of NLA_KIND_BINARY_FIXED2 to the struct size so every emission
 * matches the policy length exactly and reaches the post-validate
 * handler.  The bytes themselves stay random — that's what lets the
 * fingerprint installer and table walker get fuzzed instead of the
 * length gate.
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
