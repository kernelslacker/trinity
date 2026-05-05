/*
 * Genetlink family grammar: mptcp_pm.
 *
 * The MPTCP path manager netlink family is the userspace control
 * plane for adding / removing endpoint addresses, querying limits,
 * and steering subflow creation on multipath-TCP sockets.  It was
 * added in 5.6 alongside the rest of the MPTCP stack and has
 * accreted command coverage steadily since (SET_FLAGS, ANNOUNCE,
 * REMOVE, SUBFLOW_CREATE/DESTROY) — every release tends to ship a
 * new attribute or command, and the per-cmd nla_policy tables in
 * net/mptcp/pm_netlink.c + pm_userspace.c are exactly the kind of
 * shallow validators that benefit from spec-driven fuzzing.
 *
 * Starter command set covers the address-table side of the family:
 * ADD_ADDR / DEL_ADDR / GET_ADDR / FLUSH_ADDRS plus the limits
 * accessors (SET_LIMITS / GET_LIMITS).  These all dispatch through
 * mptcp_pm_genl_ops[] with the shared MPTCP_PM_ATTR_ADDR nested
 * outer (carrying MPTCP_PM_ADDR_ATTR_FAMILY / ADDR4 / ADDR6 / PORT
 * children) so a single nested entry at type ATTR_ADDR exercises the
 * cross-cutting address parser before each per-cmd handler runs.
 *
 * Header gating mirrors the ethtool family: <linux/mptcp_pm.h> is
 * a YNL-generated UAPI header that only exists from kernel 6.11
 * onward (older kernels carried the same constants in <linux/mptcp.h>).
 * Wrap the family in __has_include so older build hosts silently
 * drop it instead of failing the build.
 */

#if __has_include(<linux/mptcp_pm.h>)

#include <linux/mptcp_pm.h>

#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar mptcp_pm_cmds[] = {
	{ MPTCP_PM_CMD_ADD_ADDR,    "MPTCP_PM_CMD_ADD_ADDR" },
	{ MPTCP_PM_CMD_DEL_ADDR,    "MPTCP_PM_CMD_DEL_ADDR" },
	{ MPTCP_PM_CMD_GET_ADDR,    "MPTCP_PM_CMD_GET_ADDR" },
	{ MPTCP_PM_CMD_FLUSH_ADDRS, "MPTCP_PM_CMD_FLUSH_ADDRS" },
	{ MPTCP_PM_CMD_SET_LIMITS,  "MPTCP_PM_CMD_SET_LIMITS" },
	{ MPTCP_PM_CMD_GET_LIMITS,  "MPTCP_PM_CMD_GET_LIMITS" },
};

/*
 * Attribute spec table follows mptcp_pm_policy in
 * net/mptcp/pm_netlink.c:
 *   ATTR_ADDR           NESTED — outer for the per-endpoint address
 *                       descriptor (FAMILY + ADDR4|ADDR6 + optional
 *                       PORT/IF_IDX/FLAGS).  The single-table spec
 *                       emitter generates nested children from this
 *                       same array by numeric position; positions
 *                       1..6 below match the MPTCP_PM_ADDR_ATTR_*
 *                       child namespace closely enough that a
 *                       meaningful fraction of nested payloads
 *                       survive the inner validator.
 *   RCV_ADD_ADDRS       u32 — per-namespace receive limit
 *   SUBFLOWS            u32 — per-namespace subflow limit
 *   TOKEN               u32 — connection identifier (announce path)
 *   LOC_ID              u8  — local address id (subflow ops)
 *   ATTR_ADDR_REMOTE    NESTED — same shape as ATTR_ADDR but for
 *                       the remote endpoint (subflow create/destroy).
 *
 * Inline IPv4/IPv6 address payloads are 4 / 16 bytes respectively;
 * the ADDR_ATTR namespace types overlap with positions 3 and 4
 * here so the binary entries cover both.
 */
static const struct nla_attr_spec mptcp_pm_attrs[] = {
	{ MPTCP_PM_ATTR_ADDR,            NLA_KIND_NESTED, 0 },
	{ MPTCP_PM_ADDR_ATTR_FAMILY,     NLA_KIND_U16,    2 },
	{ MPTCP_PM_ADDR_ATTR_ID,         NLA_KIND_U8,     1 },
	{ MPTCP_PM_ADDR_ATTR_ADDR4,      NLA_KIND_BINARY, 4 },
	{ MPTCP_PM_ADDR_ATTR_ADDR6,      NLA_KIND_BINARY, 16 },
	{ MPTCP_PM_ADDR_ATTR_PORT,       NLA_KIND_U16,    2 },
	{ MPTCP_PM_ADDR_ATTR_FLAGS,      NLA_KIND_U32,    4 },
	{ MPTCP_PM_ADDR_ATTR_IF_IDX,     NLA_KIND_U32,    4 },
	{ MPTCP_PM_ATTR_RCV_ADD_ADDRS,   NLA_KIND_U32,    4 },
	{ MPTCP_PM_ATTR_SUBFLOWS,        NLA_KIND_U32,    4 },
	{ MPTCP_PM_ATTR_TOKEN,           NLA_KIND_U32,    4 },
	{ MPTCP_PM_ATTR_LOC_ID,          NLA_KIND_U8,     1 },
	{ MPTCP_PM_ATTR_ADDR_REMOTE,     NLA_KIND_NESTED, 0 },
};

struct genl_family_grammar fam_mptcp_pm = {
	.name = MPTCP_PM_NAME,
	.cmds = mptcp_pm_cmds,
	.n_cmds = ARRAY_SIZE(mptcp_pm_cmds),
	.attrs = mptcp_pm_attrs,
	.n_attrs = ARRAY_SIZE(mptcp_pm_attrs),
	.default_version = MPTCP_PM_VER,
};

#endif /* __has_include(<linux/mptcp_pm.h>) */
