/*
 * Genetlink family grammar: NCSI (Network Controller Sideband Interface).
 *
 * The NCSI subsystem (net/ncsi/) exposes its userspace control plane
 * through a single generic-netlink family ("NCSI") with six user-callable
 * commands: NCSI_CMD_PKG_INFO (the only command with a .dumpit handler),
 * NCSI_CMD_SET_INTERFACE / NCSI_CMD_CLEAR_INTERFACE (preferred
 * package/channel selection), NCSI_CMD_SEND_CMD (the raw NC-SI
 * passthrough that carries a binary NCSI_ATTR_DATA payload of up to
 * 2048 bytes — the most interesting fuzz target on this family), and
 * NCSI_CMD_SET_PACKAGE_MASK / NCSI_CMD_SET_CHANNEL_MASK (whitelist
 * configuration, optionally toggling multi-mode via NCSI_ATTR_MULTI_FLAG).
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "NCSI", so the per-cmd nla_policy walker in
 * net/ncsi/ncsi-netlink.c plus the NC-SI command passthrough path have
 * been routinely cold under generic netlink fuzzing; resolving the
 * family at first NETLINK_GENERIC use lets the message generator
 * address real NCSI messages whose attribute shapes plausibly survive
 * the per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample model,
 * a single flat nla_attr_spec table lists every id used by this family's
 * commands.  NCSI uses a single flat NCSI_ATTR_* namespace; the one
 * nominally nested attr (NCSI_ATTR_PACKAGE_LIST) is emitted as an empty
 * container so the kernel's nla_validate accepts it without recursing
 * into a per-package sub-policy.  The remaining seven attrs cover the
 * IFINDEX scoping selector, the package/channel id selectors, the
 * raw NC-SI command payload (DATA), the multi-mode toggle flag, and
 * the package/channel whitelist masks.
 *
 * Header gating mirrors the team / hsr / fou / psample families:
 * <linux/ncsi.h> is the upstream UAPI header carrying every NCSI_CMD_*
 * and NCSI_ATTR_* enum referenced below.  Build hosts lacking the
 * header silently drop the family from the registry instead of failing
 * the build.  Per-symbol #ifndef shims fill in every NCSI_ATTR_* /
 * NCSI_CMD_* on build hosts whose stale uapi predates the
 * PACKAGE_MASK / CHANNEL_MASK additions.
 */

#if __has_include(<linux/ncsi.h>)

#include "kernel/ncsi.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar ncsi_cmds[] = {
	{ NCSI_CMD_PKG_INFO,		"NCSI_CMD_PKG_INFO" },
	{ NCSI_CMD_SET_INTERFACE,	"NCSI_CMD_SET_INTERFACE" },
	{ NCSI_CMD_CLEAR_INTERFACE,	"NCSI_CMD_CLEAR_INTERFACE" },
	{ NCSI_CMD_SEND_CMD,		"NCSI_CMD_SEND_CMD" },
	{ NCSI_CMD_SET_PACKAGE_MASK,	"NCSI_CMD_SET_PACKAGE_MASK" },
	{ NCSI_CMD_SET_CHANNEL_MASK,	"NCSI_CMD_SET_CHANNEL_MASK" },
};

/*
 * Attribute spec follows the NCSI_ATTR_* enum in <linux/ncsi.h> and
 * mirrors ncsi_genl_policy in net/ncsi/ncsi-netlink.c.  IFINDEX,
 * PACKAGE_ID, CHANNEL_ID, PACKAGE_MASK, and CHANNEL_MASK are u32
 * scalars (the masks are 32-bit whitelists; the kernel's per-id range
 * checks live downstream of the policy walker, so listing both
 * in-range and out-of-range values is the validator's job).  DATA is
 * the raw NC-SI command payload, NLA_BINARY in the kernel policy with
 * a .len of 2048 — capped here at 256 to keep generated messages
 * bounded while still exercising the variable-length copy path that
 * the SEND_CMD handler memcpys into the NC-SI request buffer.
 * MULTI_FLAG is a presence-only flag toggling multi-mode on the
 * SET_PACKAGE_MASK / SET_CHANNEL_MASK commands.  PACKAGE_LIST is
 * NLA_NESTED in the kernel policy — emitted as an empty container so
 * nla_validate accepts it without recursing into a per-package
 * sub-policy.
 */
static const struct nla_attr_spec ncsi_attrs[] = {
	{ NCSI_ATTR_IFINDEX,		NLA_KIND_U32,    4 },
	{ NCSI_ATTR_PACKAGE_LIST,	NLA_KIND_NESTED, 0 },
	{ NCSI_ATTR_PACKAGE_ID,		NLA_KIND_U32,    4 },
	{ NCSI_ATTR_CHANNEL_ID,		NLA_KIND_U32,    4 },
	{ NCSI_ATTR_DATA,		NLA_KIND_BINARY, 256 },
	{ NCSI_ATTR_MULTI_FLAG,		NLA_KIND_FLAG,   0 },
	{ NCSI_ATTR_PACKAGE_MASK,	NLA_KIND_U32,    4 },
	{ NCSI_ATTR_CHANNEL_MASK,	NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_ncsi = {
	.name = "NCSI",
	.cmds = ncsi_cmds,
	.n_cmds = ARRAY_SIZE(ncsi_cmds),
	.attrs = ncsi_attrs,
	.n_attrs = ARRAY_SIZE(ncsi_attrs),
};

#endif /* __has_include(<linux/ncsi.h>) */
