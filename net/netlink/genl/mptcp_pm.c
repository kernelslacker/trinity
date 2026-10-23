/*
 * Genetlink family grammar: mptcp_pm (MPTCP path manager), targeting the
 * generated policies and ops in net/mptcp/mptcp_pm_gen.c and the handlers
 * in net/mptcp/pm_netlink.c.  Every op but GET_ADDR and GET_LIMITS is
 * GENL_UNS_ADMIN_PERM.
 */

#if __has_include(<linux/mptcp_pm.h>)

#include <linux/mptcp_pm.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * SET_FLAGS / ANNOUNCE / REMOVE / SUBFLOW_CREATE / SUBFLOW_DESTROY were
 * added to the family after the initial address-table opset.  The
 * numeric ids match the mptcp_pm.h enum ordering and are shimmed here
 * so a host with a partially-populated uapi header still builds under
 * -Werror.
 */
#ifndef MPTCP_PM_CMD_SET_FLAGS
#define MPTCP_PM_CMD_SET_FLAGS		7
#endif
#ifndef MPTCP_PM_CMD_ANNOUNCE
#define MPTCP_PM_CMD_ANNOUNCE		8
#endif
#ifndef MPTCP_PM_CMD_REMOVE
#define MPTCP_PM_CMD_REMOVE		9
#endif
#ifndef MPTCP_PM_CMD_SUBFLOW_CREATE
#define MPTCP_PM_CMD_SUBFLOW_CREATE	10
#endif
#ifndef MPTCP_PM_CMD_SUBFLOW_DESTROY
#define MPTCP_PM_CMD_SUBFLOW_DESTROY	11
#endif

static const struct genl_cmd_grammar mptcp_pm_cmds[] = {
	{ MPTCP_PM_CMD_ADD_ADDR,         "MPTCP_PM_CMD_ADD_ADDR" },
	{ MPTCP_PM_CMD_DEL_ADDR,         "MPTCP_PM_CMD_DEL_ADDR" },
	{ MPTCP_PM_CMD_GET_ADDR,         "MPTCP_PM_CMD_GET_ADDR" },
	{ MPTCP_PM_CMD_FLUSH_ADDRS,      "MPTCP_PM_CMD_FLUSH_ADDRS" },
	{ MPTCP_PM_CMD_SET_LIMITS,       "MPTCP_PM_CMD_SET_LIMITS" },
	{ MPTCP_PM_CMD_GET_LIMITS,       "MPTCP_PM_CMD_GET_LIMITS" },
	{ MPTCP_PM_CMD_SET_FLAGS,        "MPTCP_PM_CMD_SET_FLAGS" },
	{ MPTCP_PM_CMD_ANNOUNCE,         "MPTCP_PM_CMD_ANNOUNCE" },
	{ MPTCP_PM_CMD_REMOVE,           "MPTCP_PM_CMD_REMOVE" },
	{ MPTCP_PM_CMD_SUBFLOW_CREATE,   "MPTCP_PM_CMD_SUBFLOW_CREATE" },
	{ MPTCP_PM_CMD_SUBFLOW_DESTROY,  "MPTCP_PM_CMD_SUBFLOW_DESTROY" },
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
