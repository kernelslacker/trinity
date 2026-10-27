/*
 * Genetlink family grammar: lockd (kernel NFS lock manager), targeting
 * fs/lockd/netlink.c.  SERVER_SET is GENL_ADMIN_PERM and the only op with
 * an input policy; SERVER_GET takes no attributes.
 */

#if __has_include(<linux/lockd_netlink.h>)

#include "kernel/lockd_netlink.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * SERVER_GET is a split op with no policy, which the genl core gives a
 * reject-all one: any attribute at all is an -EINVAL, so it takes none.
 */
static const struct genl_cmd_grammar lockd_cmds[] = {
	{ LOCKD_CMD_SERVER_SET, "LOCKD_CMD_SERVER_SET" },
	{ LOCKD_CMD_SERVER_GET, "LOCKD_CMD_SERVER_GET", genl_no_attrs },
};

/*
 * lockd_server_set_nl_policy, which SERVER_SET alone draws from.  The op
 * validates strictly: GRACETIME is a u32 seconds counter, the TCP and UDP
 * listener ports are u16.  lockd_nl_server_set_doit() answers -EINVAL
 * without GRACETIME, or with one past nlm_grace_period_max, 240, a bound
 * the policy leaves to it.
 */
static const struct nla_attr_spec lockd_attrs[] = {
	{ LOCKD_A_SERVER_GRACETIME,	NLA_KIND_U32_RANGE, 240, 0,
	  .required = true },
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
