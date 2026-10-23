/*
 * Genetlink family grammar: TASKSTATS, targeting taskstats_user_cmd() in
 * kernel/taskstats.c.  TASKSTATS_CMD_GET (GENL_ADMIN_PERM) dispatches on
 * which selector attribute is present: PID, TGID, or the REGISTER_CPUMASK /
 * DEREGISTER_CPUMASK pair, which drives the cpulist parser.
 */

#include <linux/taskstats.h>

#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar taskstats_cmds[] = {
	{ TASKSTATS_CMD_GET, "TASKSTATS_CMD_GET" },
};

/*
 * Attribute spec table follows kernel/taskstats.c:
 *   PID / TGID                u32
 *   REGISTER_CPUMASK          NUL_STRING — cpumask in textual form
 *                             (e.g. "0-3,7"), capped at NR_CPUS_MAX
 *                             chars; the cpulist parser tolerates any
 *                             reasonable length up to the policy max.
 *   DEREGISTER_CPUMASK        same shape as REGISTER_CPUMASK.
 *
 * 256 bytes covers a 4096-cpu list comfortably and keeps each
 * generated payload short enough to round-trip cheaply.
 */
static const struct nla_attr_spec taskstats_attrs[] = {
	{ TASKSTATS_CMD_ATTR_PID,                  NLA_KIND_U32,    4 },
	{ TASKSTATS_CMD_ATTR_TGID,                 NLA_KIND_U32,    4 },
	{ TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,     NLA_KIND_STRING_CPULIST, 256 },
	{ TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK,   NLA_KIND_STRING_CPULIST, 256 },
};

struct genl_family_grammar fam_taskstats = {
	.name = TASKSTATS_GENL_NAME,
	.cmds = taskstats_cmds,
	.n_cmds = ARRAY_SIZE(taskstats_cmds),
	.attrs = taskstats_attrs,
	.n_attrs = ARRAY_SIZE(taskstats_attrs),
	.default_version = TASKSTATS_GENL_VERSION,
};
