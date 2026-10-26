/*
 * Genetlink family grammar: thermal (kernel thermal subsystem), targeting
 * thermal_genl_policy and the handlers in drivers/thermal/thermal_netlink.c.
 * None of its nine ops is GENL_ADMIN_PERM, but the THRESHOLD_ADD, _DELETE
 * and _FLUSH handlers test capable(CAP_SYS_ADMIN) first.  The six nested
 * containers are output-only; the input ids are read flat from the top
 * level.
 */

#if __has_include(<linux/thermal.h>)

#include "kernel/thermal.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * Per-symbol shims for the threshold interface, which landed after the
 * oldest headers we build against: the four THRESHOLD commands and the
 * three THRESHOLD attributes do not exist on a 6.12-vintage
 * <linux/thermal.h>, and referencing them unguarded fails the build
 * rather than just skipping the newer commands.  Values are the ABI
 * positions in enum thermal_genl_cmd / enum thermal_genl_attr; the same
 * per-symbol #ifndef model as mptcp_pm / cifs / ila.
 */
#ifndef THERMAL_GENL_CMD_THRESHOLD_GET
#define THERMAL_GENL_CMD_THRESHOLD_GET		7
#endif
#ifndef THERMAL_GENL_CMD_THRESHOLD_ADD
#define THERMAL_GENL_CMD_THRESHOLD_ADD		8
#endif
#ifndef THERMAL_GENL_CMD_THRESHOLD_DELETE
#define THERMAL_GENL_CMD_THRESHOLD_DELETE	9
#endif
#ifndef THERMAL_GENL_CMD_THRESHOLD_FLUSH
#define THERMAL_GENL_CMD_THRESHOLD_FLUSH	10
#endif
#ifndef THERMAL_GENL_ATTR_THRESHOLD
#define THERMAL_GENL_ATTR_THRESHOLD		24
#endif
#ifndef THERMAL_GENL_ATTR_THRESHOLD_TEMP
#define THERMAL_GENL_ATTR_THRESHOLD_TEMP	25
#endif
#ifndef THERMAL_GENL_ATTR_THRESHOLD_DIRECTION
#define THERMAL_GENL_ATTR_THRESHOLD_DIRECTION	26
#endif

/*
 * TZ_GET_MODE is in the uapi enum but thermal_genl_ops[] registers no op
 * for it, so the genl core rejects it on input; the THERMAL_GENL_EVENT_*
 * ids are the kernel-to-userspace notification channel.  THRESHOLD_ADD
 * and THRESHOLD_DELETE consume TZ_ID + THRESHOLD_TEMP +
 * THRESHOLD_DIRECTION, THRESHOLD_FLUSH only TZ_ID; the attribute table
 * carries all three.
 */
static const struct genl_cmd_grammar thermal_cmds[] = {
	{ THERMAL_GENL_CMD_TZ_GET_ID,		"THERMAL_GENL_CMD_TZ_GET_ID" },
	{ THERMAL_GENL_CMD_TZ_GET_TRIP,		"THERMAL_GENL_CMD_TZ_GET_TRIP" },
	{ THERMAL_GENL_CMD_TZ_GET_TEMP,		"THERMAL_GENL_CMD_TZ_GET_TEMP" },
	{ THERMAL_GENL_CMD_TZ_GET_GOV,		"THERMAL_GENL_CMD_TZ_GET_GOV" },
	{ THERMAL_GENL_CMD_CDEV_GET,		"THERMAL_GENL_CMD_CDEV_GET" },
	{ THERMAL_GENL_CMD_THRESHOLD_GET,	"THERMAL_GENL_CMD_THRESHOLD_GET" },
	{ THERMAL_GENL_CMD_THRESHOLD_ADD,	"THERMAL_GENL_CMD_THRESHOLD_ADD" },
	{ THERMAL_GENL_CMD_THRESHOLD_DELETE,	"THERMAL_GENL_CMD_THRESHOLD_DELETE" },
	{ THERMAL_GENL_CMD_THRESHOLD_FLUSH,	"THERMAL_GENL_CMD_THRESHOLD_FLUSH" },
};

/*
 * Attribute spec follows the THERMAL_GENL_ATTR_* enum in <linux/thermal.h>.
 * TZ_ID is the u32 thermal-zone selector every command keys on; TZ_TEMP
 * carries the millicelsius temperature reading the kernel emits on dump
 * (the policy declares it NLA_U32, and the validator's signedness check
 * is byte-pattern only).  TZ_TRIP_{ID,TYPE,TEMP,HYST} are the per-trip
 * scalars TZ_GET_TRIP enumerates; TZ_MODE carries the per-zone enabled
 * / disabled state; TZ_CDEV_WEIGHT is the per-binding governor weight;
 * TZ_NAME and TZ_GOV_NAME are the per-zone identifier strings (kernel
 * caps at THERMAL_NAME_LENGTH).  CDEV_{ID,CUR_STATE,MAX_STATE} and
 * CDEV_NAME describe the cooling device inventory CDEV_GET enumerates.
 * CPU_CAPABILITY_{ID,PERFORMANCE,EFFICIENCY} carry the per-CPU capacity
 * triple the kernel emits on capability-change events; listing them
 * lets the generator round-trip what the kernel may parse back, the
 * same way the OVS dp/flow STATS attrs do.  THRESHOLD_TEMP /
 * THRESHOLD_DIRECTION are the per-threshold scalars THRESHOLD_GET
 * enumerates (TEMP in millicelsius, DIRECTION one of
 * THERMAL_THRESHOLD_WAY_UP / WAY_DOWN).  TZ / TZ_TRIP / TZ_GOV /
 * CDEV / CPU_CAPABILITY / THRESHOLD are bare NLA_NESTED in
 * thermal_genl_policy that the kernel only emits in replies: no handler
 * parses a nest, and the three ids the handlers read (TZ_ID,
 * THRESHOLD_TEMP, THRESHOLD_DIRECTION) are top-level attrs.  GOV_NAME
 * and TZ_PREV_TEMP are emitted by the kernel but absent from the input
 * policy, so they have no entry.
 */
static const struct nla_attr_spec thermal_attrs[] = {
	{ THERMAL_GENL_ATTR_TZ,				NLA_KIND_NESTED, 0 },
	{ THERMAL_GENL_ATTR_TZ_ID,			NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_TZ_TEMP,			NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_TZ_TRIP,			NLA_KIND_NESTED, 0 },
	{ THERMAL_GENL_ATTR_TZ_TRIP_ID,			NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_TZ_TRIP_TYPE,		NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_TZ_TRIP_TEMP,		NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_TZ_TRIP_HYST,		NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_TZ_MODE,			NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_TZ_NAME,			NLA_KIND_STRING, THERMAL_NAME_LENGTH - 1 },
	{ THERMAL_GENL_ATTR_TZ_CDEV_WEIGHT,		NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_TZ_GOV,			NLA_KIND_NESTED, 0 },
	{ THERMAL_GENL_ATTR_TZ_GOV_NAME,		NLA_KIND_STRING, THERMAL_NAME_LENGTH - 1 },
	{ THERMAL_GENL_ATTR_CDEV,			NLA_KIND_NESTED, 0 },
	{ THERMAL_GENL_ATTR_CDEV_ID,			NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_CDEV_CUR_STATE,		NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_CDEV_MAX_STATE,		NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_CDEV_NAME,			NLA_KIND_STRING, THERMAL_NAME_LENGTH - 1 },
	{ THERMAL_GENL_ATTR_CPU_CAPABILITY,		NLA_KIND_NESTED, 0 },
	{ THERMAL_GENL_ATTR_CPU_CAPABILITY_ID,		NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_CPU_CAPABILITY_PERFORMANCE,	NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_CPU_CAPABILITY_EFFICIENCY,	NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_THRESHOLD,			NLA_KIND_NESTED, 0 },
	{ THERMAL_GENL_ATTR_THRESHOLD_TEMP,		NLA_KIND_U32,    4 },
	{ THERMAL_GENL_ATTR_THRESHOLD_DIRECTION,	NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_thermal = {
	.name = "thermal",
	.cmds = thermal_cmds,
	.n_cmds = ARRAY_SIZE(thermal_cmds),
	.attrs = thermal_attrs,
	.n_attrs = ARRAY_SIZE(thermal_attrs),
};

#endif /* __has_include(<linux/thermal.h>) */
