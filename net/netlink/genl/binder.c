/*
 * Genetlink family grammar: binder (Android binder transaction reports),
 * targeting drivers/android/binder_netlink.c.  Its op table is empty, so a
 * send is answered -EOPNOTSUPP at the op lookup, before any attribute is
 * parsed; the grammar exists to reach that path with a real family_id.
 */

#include "kernel/binder_netlink.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar binder_cmds[] = {
	{ BINDER_CMD_REPORT, "BINDER_CMD_REPORT" },
};

/*
 * Sizes follow the nla_put_*() calls in binder_netlink_report()
 * (drivers/android/binder.c): CONTEXT is a string, IS_REPLY a flag, the
 * rest u32.  One flat namespace, no nested containers.
 */
static const struct nla_attr_spec binder_attrs[] = {
	{ BINDER_A_REPORT_ERROR,     NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_CONTEXT,   NLA_KIND_STRING, 32 },
	{ BINDER_A_REPORT_FROM_PID,  NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_FROM_TID,  NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_TO_PID,    NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_TO_TID,    NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_IS_REPLY,  NLA_KIND_FLAG,   0 },
	{ BINDER_A_REPORT_FLAGS,     NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_CODE,      NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_DATA_SIZE, NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_binder = {
	.name = BINDER_FAMILY_NAME,
	.cmds = binder_cmds,
	.n_cmds = ARRAY_SIZE(binder_cmds),
	.attrs = binder_attrs,
	.n_attrs = ARRAY_SIZE(binder_attrs),
	.default_version = BINDER_FAMILY_VERSION,
};
