/*
 * Genetlink family grammar: lockd (kernel NFS lock manager), targeting
 * fs/lockd/netlink.c.  SERVER_SET is GENL_ADMIN_PERM and the only op with
 * an input policy; SERVER_GET takes no attributes.
 */

#if __has_include(<linux/lockd_netlink.h>)

#include "kernel/lockd_netlink.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar lockd_cmds[] = {
	{ LOCKD_CMD_SERVER_SET, "LOCKD_CMD_SERVER_SET" },
	{ LOCKD_CMD_SERVER_GET, "LOCKD_CMD_SERVER_GET" },
};

/*
 * Attribute spec follows the LOCKD_A_SERVER_* enum in
 * <linux/lockd_netlink.h>.  GRACETIME is a u32 seconds counter; the
 * TCP and UDP listener ports are u16 wire-encoded port numbers.
 * SERVER_GET takes no attributes and responds with the current values,
 * SERVER_SET ingests them, so a single flat table covers the whole
 * family with no per-command namespace needed.
 */
static const struct nla_attr_spec lockd_attrs[] = {
	{ LOCKD_A_SERVER_GRACETIME,	NLA_KIND_U32, 4 },
	{ LOCKD_A_SERVER_TCP_PORT,	NLA_KIND_U16, 2 },
	{ LOCKD_A_SERVER_UDP_PORT,	NLA_KIND_U16, 2 },
};

struct genl_family_grammar fam_lockd = {
	.name = LOCKD_FAMILY_NAME,
	.cmds = lockd_cmds,
	.n_cmds = ARRAY_SIZE(lockd_cmds),
	.attrs = lockd_attrs,
	.n_attrs = ARRAY_SIZE(lockd_attrs),
	.default_version = LOCKD_FAMILY_VERSION,
};

#endif /* __has_include(<linux/lockd_netlink.h>) */
