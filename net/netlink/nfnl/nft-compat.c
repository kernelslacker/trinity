/*
 * NETLINK_NETFILTER subsystem grammar: nft_compat (NFNL_SUBSYS_NFT_COMPAT),
 * targeting nfnl_compat_get_rcu() in net/netfilter/nft_compat.c.  The handler
 * returns -EINVAL unless NAME, REV and TYPE are all present, then resolves
 * them with xt_find_revision(), loading the xt module by name on a miss.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables_compat.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar nft_compat_cmds[] = {
	{ NFNL_MSG_COMPAT_GET, "NFNL_MSG_COMPAT_GET" },
};

/*
 * nfnl_compat_policy_get types NFTA_COMPAT_TYPE a plain NLA_U32, but
 * nfnl_compat_get_rcu() reads target = (nla_get_be32() == htonl(1)): 1 is a
 * target and any other number a match, so 0 and 1 reach both arms.
 */
static const unsigned int nft_compat_types[] = { 0, 1 };

/*
 * NFTA_COMPAT_REV is NLA_POLICY_MAX(NLA_BE32, 255) in nfnl_compat_policy_get.
 */
static const struct nla_attr_spec nft_compat_attrs[] = {
	{ NFTA_COMPAT_NAME, NLA_KIND_STRING, NFT_COMPAT_NAME_MAX - 1 },
	{ NFTA_COMPAT_REV,  NLA_KIND_BE32_MAX, 255 },
	{ NFTA_COMPAT_TYPE, NLA_KIND_BE32_ONEOF, 0, 0,
	  .oneof = nft_compat_types, .n_oneof = ARRAY_SIZE(nft_compat_types) },
};

struct nfnl_subsys_grammar sub_nft_compat = {
	.name = "nft_compat",
	.subsys_id = NFNL_SUBSYS_NFT_COMPAT,
	.cmds = nft_compat_cmds,
	.n_cmds = ARRAY_SIZE(nft_compat_cmds),
	.attrs = nft_compat_attrs,
	.n_attrs = ARRAY_SIZE(nft_compat_attrs),
};
