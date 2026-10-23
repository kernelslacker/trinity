/*
 * Genetlink family grammar: NCSI (Network Controller Sideband Interface),
 * targeting ncsi_genl_policy in net/ncsi/ncsi-netlink.c.  Every op but
 * PKG_INFO is GENL_ADMIN_PERM.  One flat NCSI_ATTR_* namespace.
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
 * SET_PACKAGE_MASK / SET_CHANNEL_MASK commands.  PACKAGE_LIST is a
 * bare NLA_NESTED in the kernel policy that only PKG_INFO replies
 * carry; nothing parses it on input, so it has no sub-policy.
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
