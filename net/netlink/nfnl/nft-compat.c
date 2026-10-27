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

/*
 * nfnl_compat_policy_get types NFTA_COMPAT_TYPE a plain NLA_U32, but
 * nfnl_compat_get_rcu() reads target = (nla_get_be32() == htonl(1)): 1 is a
 * target and any other number a match, so 0 and 1 reach both arms.
 */
static const unsigned int nft_compat_types[] = { 0, 1 };

/*
 * xt_find_revision() looks the name up among the matches, or for a TYPE of 1
 * the targets, registered for the family, and try_then_request_module() runs
 * modprobe for "ipt_<name>" and its kin when there is none, so a name drawn
 * at random costs a module request on every call.  These are the matches
 * that xt_tcpudp.c, xt_mark.c, xt_limit.c, xt_state.c, xt_conntrack.c,
 * xt_comment.c and xt_pkttype.c register, and the targets that xt_mark.c,
 * xt_NFQUEUE.c, xt_CT.c, xt_NFLOG.c, xt_TRACE.c and xt_CLASSIFY.c do, each
 * for IPv4 and IPv6 or for every family, under module aliases that load them.
 * TYPE is drawn without regard to the name, so about half the names meet the
 * kind they are, and the rest cost one request.
 */
static const char *const nft_compat_names[] = {
	"tcp", "udp", "mark", "limit", "state", "conntrack", "comment",
	"pkttype", "MARK", "NFQUEUE", "CT", "NFLOG", "TRACE", "CLASSIFY",
};

/*
 * NFTA_COMPAT_REV is NLA_POLICY_MAX(NLA_BE32, 255) in nfnl_compat_policy_get,
 * but xt_find_revision() has an extension only at the revision it registers
 * and answers any other -EPROTONOSUPPORT, and nfnl_compat_get_rcu() reaches
 * nfnl_compat_fill_info() only with one that exists.  The extensions above
 * have revisions 0 to 3, xt_conntrack and xt_NFQUEUE running to 3 and no
 * other past 2, so those are the numbers worth sending; the draw in eight
 * that is random bytes is over 255 almost every time and meets the policy.
 */
static const unsigned int nft_compat_revs[] = { 0, 1, 2, 3 };

/*
 * The one command's table.  nfnl_compat_get_rcu() answers -EINVAL unless the
 * name, REV and TYPE are all there, so all three are marked.
 */
static const struct nla_attr_spec nft_compat_attrs[] = {
	{ NFTA_COMPAT_NAME, NLA_KIND_STRING_ONEOF, 0, 0,
	  .words = nft_compat_names, .n_words = ARRAY_SIZE(nft_compat_names),
	  .required = true },
	{ NFTA_COMPAT_REV,  NLA_KIND_BE32_ONEOF, 0, 0,
	  .oneof = nft_compat_revs, .n_oneof = ARRAY_SIZE(nft_compat_revs),
	  .required = true },
	{ NFTA_COMPAT_TYPE, NLA_KIND_BE32_ONEOF, 0, 0,
	  .oneof = nft_compat_types, .n_oneof = ARRAY_SIZE(nft_compat_types),
	  .required = true },
};

static const struct nfnl_cmd_grammar nft_compat_cmds[] = {
	{ NFNL_MSG_COMPAT_GET, "NFNL_MSG_COMPAT_GET", false,
	  nft_compat_attrs, ARRAY_SIZE(nft_compat_attrs) },
};

struct nfnl_subsys_grammar sub_nft_compat = {
	.name = "nft_compat",
	.subsys_id = NFNL_SUBSYS_NFT_COMPAT,
	.cmds = nft_compat_cmds,
	.n_cmds = ARRAY_SIZE(nft_compat_cmds),
};
