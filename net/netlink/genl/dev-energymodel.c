/*
 * Genetlink family grammar: dev-energymodel (energy model performance
 * domain readback), targeting kernel/power/em_netlink_autogen.c and
 * em_netlink.c.  Neither of its two ops is GENL_ADMIN_PERM.
 */

#if __has_include(<linux/dev_energymodel.h>)

#include "kernel/dev_energymodel.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * PERF_DOMAIN_CREATED / _UPDATED / _DELETED are kernel-emitted
 * notifications with no inbound handler, so they are not listed.
 */
static const struct genl_cmd_grammar dev_energymodel_cmds[] = {
	{ DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS, "DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS" },
	{ DEV_ENERGYMODEL_CMD_GET_PERF_TABLE,	"DEV_ENERGYMODEL_CMD_GET_PERF_TABLE" },
};

/*
 * Attribute spec follows the DEV_ENERGYMODEL_A_PERF_DOMAIN_* and
 * DEV_ENERGYMODEL_A_PERF_TABLE_* enums in <linux/dev_energymodel.h>.
 * GET_PERF_DOMAINS' request-side policy (em_netlink_autogen.c) has
 * maxattr = DEV_ENERGYMODEL_A_PERF_DOMAIN_PERF_DOMAIN_ID (wire id 2)
 * with a single NLA_U32 entry at that id; GET_PERF_TABLE's policy has
 * maxattr = DEV_ENERGYMODEL_A_PERF_TABLE_PERF_DOMAIN_ID (wire id 1)
 * also with a single NLA_U32 entry.  Listing both lets the message
 * generator emit either id as a u32 against either command: the
 * matching pair lands in the doit handler, the mismatched pair (wire
 * id 1 against GET_PERF_DOMAINS, or wire id 2 against GET_PERF_TABLE)
 * exercises the per-cmd policy walker's reject branch.
 */
static const struct nla_attr_spec dev_energymodel_attrs[] = {
	{ DEV_ENERGYMODEL_A_PERF_DOMAIN_PERF_DOMAIN_ID,	NLA_KIND_U32, 4 },
	{ DEV_ENERGYMODEL_A_PERF_TABLE_PERF_DOMAIN_ID,	NLA_KIND_U32, 4 },
};

struct genl_family_grammar fam_dev_energymodel = {
	.name = DEV_ENERGYMODEL_FAMILY_NAME,
	.cmds = dev_energymodel_cmds,
	.n_cmds = ARRAY_SIZE(dev_energymodel_cmds),
	.attrs = dev_energymodel_attrs,
	.n_attrs = ARRAY_SIZE(dev_energymodel_attrs),
	.default_version = DEV_ENERGYMODEL_FAMILY_VERSION,
};

#endif /* __has_include(<linux/dev_energymodel.h>) */
