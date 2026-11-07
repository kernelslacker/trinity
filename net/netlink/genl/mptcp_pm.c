/*
 * Genetlink family grammar: mptcp_pm (MPTCP path manager), targeting the
 * generated policies and ops in net/mptcp/mptcp_pm_gen.c and the handlers
 * in net/mptcp/pm_netlink.c, pm_kernel.c and pm_userspace.c.  Every op but
 * GET_ADDR and GET_LIMITS is GENL_UNS_ADMIN_PERM.
 */

#if __has_include(<linux/mptcp_pm.h>)

#include <sys/socket.h>
#include <linux/mptcp_pm.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * The address nest, mptcp_pm_address_nl_policy, whose ids are its own.
 * mptcp_pm_parse_pm_addr_attr() answers -EINVAL to a nest without FAMILY
 * where the op needs one (ADD_ADDR, ANNOUNCE and the subflow ops), to a
 * FAMILY other than AF_INET and AF_INET6, and to a nest without the
 * address of the family it names; a mark cannot pick that address, so
 * both are marked.  ADDR4 is an NLA_BE32 and ADDR6 exactly 16 bytes, and
 * IF_IDX is an NLA_S32.
 */
static const unsigned int mptcp_pm_families[] = { AF_INET, AF_INET6 };

static const struct nla_attr_spec mptcp_pm_addr_attrs[] = {
	{ MPTCP_PM_ADDR_ATTR_FAMILY,	NLA_KIND_U16_ONEOF, 0, 0,
	  .oneof = mptcp_pm_families, .n_oneof = ARRAY_SIZE(mptcp_pm_families),
	  .required = true },
	{ MPTCP_PM_ADDR_ATTR_ID,	NLA_KIND_U8,     1 },
	{ MPTCP_PM_ADDR_ATTR_ADDR4,	NLA_KIND_U32,    4, .required = true },
	{ MPTCP_PM_ADDR_ATTR_ADDR6,	NLA_KIND_BINARY, 16, 16, .required = true },
	{ MPTCP_PM_ADDR_ATTR_PORT,	NLA_KIND_U16,    2 },
	{ MPTCP_PM_ADDR_ATTR_FLAGS,	NLA_KIND_U32,    4 },
	{ MPTCP_PM_ADDR_ATTR_IF_IDX,	NLA_KIND_U32,    4 },
};

#define MPTCP_PM_ADDR_SPEC(type, ...) \
	{ type,	NLA_KIND_NESTED, 0, 0, \
	  mptcp_pm_addr_attrs, ARRAY_SIZE(mptcp_pm_addr_attrs), ##__VA_ARGS__ }

/*
 * Each op takes the table of its own policy; they all validate liberally.
 * ADD_ADDR and DEL_ADDR need the endpoint, and FLUSH_ADDRS reads nothing.
 * GET_ADDR's doit needs the address, and SET_FLAGS the local one and,
 * when TOKEN names a connection of the userspace PM, the remote one, which
 * a mark cannot say.  The userspace PM's ANNOUNCE, REMOVE and subflow ops
 * look the connection up by TOKEN and need the address, the local id and
 * both ends respectively.  SET_LIMITS answers -EINVAL to a limit above
 * MPTCP_PM_SUBFLOWS_MAX, 64; GET_LIMITS's policy takes the same two and
 * its doit reads neither.
 */
static const struct nla_attr_spec mptcp_pm_endpoint_attrs[] = {
	MPTCP_PM_ADDR_SPEC(MPTCP_PM_ENDPOINT_ADDR),
};

static const struct nla_attr_spec mptcp_pm_get_addr_attrs[] = {
	MPTCP_PM_ADDR_SPEC(MPTCP_PM_ATTR_ADDR, .required = true),
	{ MPTCP_PM_ATTR_TOKEN,		NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec mptcp_pm_set_limits_attrs[] = {
	{ MPTCP_PM_ATTR_RCV_ADD_ADDRS,	NLA_KIND_U32_RANGE, 64 },
	{ MPTCP_PM_ATTR_SUBFLOWS,	NLA_KIND_U32_RANGE, 64 },
};

static const struct nla_attr_spec mptcp_pm_get_limits_attrs[] = {
	{ MPTCP_PM_ATTR_RCV_ADD_ADDRS,	NLA_KIND_U32,    4 },
	{ MPTCP_PM_ATTR_SUBFLOWS,	NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec mptcp_pm_set_flags_attrs[] = {
	MPTCP_PM_ADDR_SPEC(MPTCP_PM_ATTR_ADDR, .required = true),
	{ MPTCP_PM_ATTR_TOKEN,		NLA_KIND_U32,    4 },
	MPTCP_PM_ADDR_SPEC(MPTCP_PM_ATTR_ADDR_REMOTE),
};

static const struct nla_attr_spec mptcp_pm_announce_attrs[] = {
	MPTCP_PM_ADDR_SPEC(MPTCP_PM_ATTR_ADDR, .required = true),
	{ MPTCP_PM_ATTR_TOKEN,		NLA_KIND_U32,    4, .required = true },
};

static const struct nla_attr_spec mptcp_pm_remove_attrs[] = {
	{ MPTCP_PM_ATTR_TOKEN,		NLA_KIND_U32,    4, .required = true },
	{ MPTCP_PM_ATTR_LOC_ID,		NLA_KIND_U8,     1, .required = true },
};

static const struct nla_attr_spec mptcp_pm_subflow_attrs[] = {
	MPTCP_PM_ADDR_SPEC(MPTCP_PM_ATTR_ADDR, .required = true),
	{ MPTCP_PM_ATTR_TOKEN,		NLA_KIND_U32,    4, .required = true },
	MPTCP_PM_ADDR_SPEC(MPTCP_PM_ATTR_ADDR_REMOTE, .required = true),
};

static const struct genl_cmd_grammar mptcp_pm_cmds[] = {
	{ MPTCP_PM_CMD_ADD_ADDR,         "MPTCP_PM_CMD_ADD_ADDR",
	  mptcp_pm_endpoint_attrs, ARRAY_SIZE(mptcp_pm_endpoint_attrs) },
	{ MPTCP_PM_CMD_DEL_ADDR,         "MPTCP_PM_CMD_DEL_ADDR",
	  mptcp_pm_endpoint_attrs, ARRAY_SIZE(mptcp_pm_endpoint_attrs) },
	{ MPTCP_PM_CMD_GET_ADDR,         "MPTCP_PM_CMD_GET_ADDR",
	  mptcp_pm_get_addr_attrs, ARRAY_SIZE(mptcp_pm_get_addr_attrs) },
	{ MPTCP_PM_CMD_FLUSH_ADDRS,      "MPTCP_PM_CMD_FLUSH_ADDRS",
	  mptcp_pm_endpoint_attrs, ARRAY_SIZE(mptcp_pm_endpoint_attrs) },
	{ MPTCP_PM_CMD_SET_LIMITS,       "MPTCP_PM_CMD_SET_LIMITS",
	  mptcp_pm_set_limits_attrs, ARRAY_SIZE(mptcp_pm_set_limits_attrs) },
	{ MPTCP_PM_CMD_GET_LIMITS,       "MPTCP_PM_CMD_GET_LIMITS",
	  mptcp_pm_get_limits_attrs, ARRAY_SIZE(mptcp_pm_get_limits_attrs) },
	{ MPTCP_PM_CMD_SET_FLAGS,        "MPTCP_PM_CMD_SET_FLAGS",
	  mptcp_pm_set_flags_attrs, ARRAY_SIZE(mptcp_pm_set_flags_attrs) },
	{ MPTCP_PM_CMD_ANNOUNCE,         "MPTCP_PM_CMD_ANNOUNCE",
	  mptcp_pm_announce_attrs, ARRAY_SIZE(mptcp_pm_announce_attrs) },
	{ MPTCP_PM_CMD_REMOVE,           "MPTCP_PM_CMD_REMOVE",
	  mptcp_pm_remove_attrs, ARRAY_SIZE(mptcp_pm_remove_attrs) },
	{ MPTCP_PM_CMD_SUBFLOW_CREATE,   "MPTCP_PM_CMD_SUBFLOW_CREATE",
	  mptcp_pm_subflow_attrs, ARRAY_SIZE(mptcp_pm_subflow_attrs) },
	{ MPTCP_PM_CMD_SUBFLOW_DESTROY,  "MPTCP_PM_CMD_SUBFLOW_DESTROY",
	  mptcp_pm_subflow_attrs, ARRAY_SIZE(mptcp_pm_subflow_attrs) },
};

struct genl_family_grammar fam_mptcp_pm = {
	.name = MPTCP_PM_NAME,
	.cmds = mptcp_pm_cmds,
	.n_cmds = ARRAY_SIZE(mptcp_pm_cmds),
	.default_version = MPTCP_PM_VER,
};

#endif /* __has_include(<linux/mptcp_pm.h>) */
