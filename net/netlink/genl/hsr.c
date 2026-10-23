/*
 * Genetlink family grammar: hsr (High-availability Seamless Redundancy,
 * IEC 62439-3), targeting net/hsr/hsr_netlink.c.  Only GET_NODE_STATUS and
 * GET_NODE_LIST are ops; both need HSR_A_IFINDEX to name an HSR master.
 * One flat HSR_A_* namespace.
 */

#if __has_include(<linux/hsr_netlink.h>)

#include <linux/if_ether.h>
#include <linux/hsr_netlink.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * RING_ERROR and NODE_DOWN are notifications, and SET_NODE_STATUS /
 * SET_NODE_LIST label the replies; none is an op, so they are not listed.
 */
static const struct genl_cmd_grammar hsr_cmds[] = {
	{ HSR_C_GET_NODE_STATUS,	"HSR_C_GET_NODE_STATUS" },
	{ HSR_C_GET_NODE_LIST,		"HSR_C_GET_NODE_LIST" },
};

/*
 * Attribute spec follows the HSR_A_* enum in <linux/hsr_netlink.h>.
 * HSR_A_NODE_ADDR / HSR_A_NODE_ADDR_B are MAC addresses (ETH_ALEN
 * bytes).  HSR_A_IF{1,2}_SEQ are u16 sequence numbers; everything
 * else (IFINDEX selector, per-port age counters, per-port ifindex
 * pair, B-side ifindex) is a u32.  The kernel's hsr_genl_policy
 * validates a subset of these on input; the remainder are response-
 * side payloads emitted by GET_NODE_STATUS / GET_NODE_LIST.  Listing
 * them all here exercises the validator's "ignore on input" branch
 * the same way the OVS dp/flow STATS attrs do.
 */
static const struct nla_attr_spec hsr_attrs[] = {
	{ HSR_A_NODE_ADDR,		NLA_KIND_BINARY, ETH_ALEN },
	{ HSR_A_IFINDEX,		NLA_KIND_U32,    4 },
	{ HSR_A_IF1_AGE,		NLA_KIND_U32,    4 },
	{ HSR_A_IF2_AGE,		NLA_KIND_U32,    4 },
	{ HSR_A_NODE_ADDR_B,		NLA_KIND_BINARY, ETH_ALEN },
	{ HSR_A_IF1_SEQ,		NLA_KIND_U16,    2 },
	{ HSR_A_IF2_SEQ,		NLA_KIND_U16,    2 },
	{ HSR_A_IF1_IFINDEX,		NLA_KIND_U32,    4 },
	{ HSR_A_IF2_IFINDEX,		NLA_KIND_U32,    4 },
	{ HSR_A_ADDR_B_IFINDEX,		NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_hsr = {
	.name = "HSR",
	.cmds = hsr_cmds,
	.n_cmds = ARRAY_SIZE(hsr_cmds),
	.attrs = hsr_attrs,
	.n_attrs = ARRAY_SIZE(hsr_attrs),
};

#endif /* __has_include(<linux/hsr_netlink.h>) */
