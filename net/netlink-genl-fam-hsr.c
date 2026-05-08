/*
 * Genetlink family grammar: hsr (NET_HSR / High-availability Seamless
 * Redundancy, IEC 62439-3).
 *
 * The HSR/PRP driver exposes its userspace control plane through a
 * single generic-netlink family ("hsr") with six user-callable
 * commands: HSR_C_RING_ERROR, HSR_C_NODE_DOWN, HSR_C_GET_NODE_STATUS,
 * HSR_C_SET_NODE_STATUS, HSR_C_GET_NODE_LIST, and HSR_C_SET_NODE_LIST.
 * Every command gates on HSR_A_IFINDEX referencing an existing HSR
 * netdev; on a host with no HSR device every path bails -ENODEV after
 * the full attribute walk completes — that's the parser-level coverage
 * spec-driven fuzzing exists to provide.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "hsr", so the per-cmd nla_policy walker in
 * net/hsr/hsr_netlink.c plus the node-table lookup paths have been
 * routinely cold under generic netlink fuzzing; resolving the family
 * at first NETLINK_GENERIC use lets the message generator address real
 * hsr messages whose attribute shapes plausibly survive the per-cmd
 * policy.
 *
 * Per the wireguard / tipc / l2tp / team model, a single flat
 * nla_attr_spec table lists every id used by this family's commands.
 * HSR uses a single flat HSR_A_* namespace (no nested containers), so
 * the table is simpler than the team / l2tp grammars: ten scalar /
 * binary attrs covering the IFINDEX selector, the per-port age and
 * sequence counters, and the MAC address pair plus per-port ifindex
 * triple emitted by the GET_NODE_STATUS / GET_NODE_LIST responses.
 *
 * Header gating mirrors the team / l2tp families: <linux/hsr_netlink.h>
 * is the upstream UAPI header carrying every HSR_C_* and HSR_A_* enum
 * referenced below.  Build hosts lacking the header silently drop the
 * family from the registry instead of failing the build.
 */

#if __has_include(<linux/hsr_netlink.h>)

#include <linux/if_ether.h>
#include <linux/hsr_netlink.h>

#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar hsr_cmds[] = {
	{ HSR_C_RING_ERROR,		"HSR_C_RING_ERROR" },
	{ HSR_C_NODE_DOWN,		"HSR_C_NODE_DOWN" },
	{ HSR_C_GET_NODE_STATUS,	"HSR_C_GET_NODE_STATUS" },
	{ HSR_C_SET_NODE_STATUS,	"HSR_C_SET_NODE_STATUS" },
	{ HSR_C_GET_NODE_LIST,		"HSR_C_GET_NODE_LIST" },
	{ HSR_C_SET_NODE_LIST,		"HSR_C_SET_NODE_LIST" },
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
 * the same way the OVS dp/flow STATS attrs and the L2TP STATS sub-
 * namespace do.
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
	.name = "hsr",
	.cmds = hsr_cmds,
	.n_cmds = ARRAY_SIZE(hsr_cmds),
	.attrs = hsr_attrs,
	.n_attrs = ARRAY_SIZE(hsr_attrs),
};

#endif /* __has_include(<linux/hsr_netlink.h>) */
