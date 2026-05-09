/*
 * Genetlink family grammar: thermal (kernel thermal subsystem).
 *
 * The thermal core exposes its userspace control plane through a single
 * generic-netlink family ("thermal") whose user-callable commands are
 * the read-side accessors over the per-net thermal_zone / cooling_device
 * inventory: TZ_GET_ID enumerates registered thermal zones, TZ_GET_TRIP
 * walks a zone's trip-point table, TZ_GET_TEMP samples the current
 * temperature, TZ_GET_GOV reads the bound governor, CDEV_GET enumerates
 * cooling devices, and THRESHOLD_GET dumps the per-zone user-thresholds
 * list.  All six gate primarily on TZ_ID; the GOV / CDEV / THRESHOLD
 * paths additionally consume the per-object selectors named after them.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "thermal", so the per-cmd nla_policy walker in
 * drivers/thermal/thermal_netlink.c has been routinely cold under
 * generic netlink fuzzing; resolving the family at first NETLINK_GENERIC
 * use lets the message generator address real thermal messages whose
 * attribute shapes plausibly survive the per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample / ila /
 * ioam6 / seg6 model, a single flat nla_attr_spec table lists every id
 * used by this family's commands.  The thermal policy carries six
 * nominally nested container attrs (TZ / TZ_TRIP / TZ_GOV / CDEV /
 * CPU_CAPABILITY / THRESHOLD); each is emitted as an empty NLA_NESTED
 * placeholder so the kernel's nla_validate accepts the message without
 * recursing into a per-sub-policy that we haven't built.  The remaining
 * scalars cover the TZ_ID / TZ_TEMP / TZ_TRIP_{ID,TYPE,TEMP,HYST} /
 * TZ_MODE / TZ_CDEV_WEIGHT / CDEV_{ID,CUR_STATE,MAX_STATE} /
 * CPU_CAPABILITY_{ID,PERFORMANCE,EFFICIENCY} / THRESHOLD_{TEMP,DIRECTION}
 * u32 selectors and the TZ_NAME / TZ_GOV_NAME / CDEV_NAME strings
 * (kernel policy caps at THERMAL_NAME_LENGTH).  GOV_NAME and
 * TZ_PREV_TEMP are response-side only — emitted by the kernel on dump
 * but absent from the input policy — so they are intentionally omitted.
 *
 * The kernel exposes additional THRESHOLD_ADD / THRESHOLD_DELETE /
 * THRESHOLD_FLUSH commands that mutate per-zone user-threshold state;
 * those are write-shape and out of scope for the read-only walker, so
 * they are intentionally omitted.  The THERMAL_GENL_EVENT_* enum is
 * the kernel-to-userspace notification channel and is not callable
 * from userspace at all.
 *
 * Header gating mirrors the psample / ila / fou / hsr / seg6 families:
 * <linux/thermal.h> is the upstream UAPI header carrying every
 * THERMAL_GENL_CMD_* and THERMAL_GENL_ATTR_* enum referenced below.
 * Build hosts lacking the header silently drop the family from the
 * registry instead of failing the build.  Per-symbol #ifndef shims
 * fill in newer THERMAL_GENL_ATTR_* / THERMAL_GENL_CMD_* on build hosts
 * whose stale uapi predates the post-6.7 CPU_CAPABILITY triple and the
 * post-6.10 THRESHOLD_* additions.
 */

#if __has_include(<linux/thermal.h>)

#include <linux/thermal.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * Per-symbol shims for THERMAL_GENL_ATTR_* / THERMAL_GENL_CMD_* ids.
 * Build hosts whose <linux/thermal.h> predates a given attribute (the
 * post-6.7 CPU_CAPABILITY / CPU_CAPABILITY_ID / CPU_CAPABILITY_PERFORMANCE
 * / CPU_CAPABILITY_EFFICIENCY quadruple, the post-6.10 THRESHOLD /
 * THRESHOLD_TEMP / THRESHOLD_DIRECTION triple) silently miss it from the
 * validator coverage; the fallback values match the upstream uapi enum
 * ordering so the wire-format ids the kernel parses match the ones the
 * generator emits.  THERMAL_GENL_CMD_THRESHOLD_GET likewise falls back
 * to the upstream enum value.
 */
#ifndef THERMAL_NAME_LENGTH
#define THERMAL_NAME_LENGTH			20
#endif

#ifndef THERMAL_GENL_ATTR_TZ
#define THERMAL_GENL_ATTR_TZ			1
#endif
#ifndef THERMAL_GENL_ATTR_TZ_ID
#define THERMAL_GENL_ATTR_TZ_ID			2
#endif
#ifndef THERMAL_GENL_ATTR_TZ_TEMP
#define THERMAL_GENL_ATTR_TZ_TEMP		3
#endif
#ifndef THERMAL_GENL_ATTR_TZ_TRIP
#define THERMAL_GENL_ATTR_TZ_TRIP		4
#endif
#ifndef THERMAL_GENL_ATTR_TZ_TRIP_ID
#define THERMAL_GENL_ATTR_TZ_TRIP_ID		5
#endif
#ifndef THERMAL_GENL_ATTR_TZ_TRIP_TYPE
#define THERMAL_GENL_ATTR_TZ_TRIP_TYPE		6
#endif
#ifndef THERMAL_GENL_ATTR_TZ_TRIP_TEMP
#define THERMAL_GENL_ATTR_TZ_TRIP_TEMP		7
#endif
#ifndef THERMAL_GENL_ATTR_TZ_TRIP_HYST
#define THERMAL_GENL_ATTR_TZ_TRIP_HYST		8
#endif
#ifndef THERMAL_GENL_ATTR_TZ_MODE
#define THERMAL_GENL_ATTR_TZ_MODE		9
#endif
#ifndef THERMAL_GENL_ATTR_TZ_NAME
#define THERMAL_GENL_ATTR_TZ_NAME		10
#endif
#ifndef THERMAL_GENL_ATTR_TZ_CDEV_WEIGHT
#define THERMAL_GENL_ATTR_TZ_CDEV_WEIGHT	11
#endif
#ifndef THERMAL_GENL_ATTR_TZ_GOV
#define THERMAL_GENL_ATTR_TZ_GOV		12
#endif
#ifndef THERMAL_GENL_ATTR_TZ_GOV_NAME
#define THERMAL_GENL_ATTR_TZ_GOV_NAME		13
#endif
#ifndef THERMAL_GENL_ATTR_CDEV
#define THERMAL_GENL_ATTR_CDEV			14
#endif
#ifndef THERMAL_GENL_ATTR_CDEV_ID
#define THERMAL_GENL_ATTR_CDEV_ID		15
#endif
#ifndef THERMAL_GENL_ATTR_CDEV_CUR_STATE
#define THERMAL_GENL_ATTR_CDEV_CUR_STATE	16
#endif
#ifndef THERMAL_GENL_ATTR_CDEV_MAX_STATE
#define THERMAL_GENL_ATTR_CDEV_MAX_STATE	17
#endif
#ifndef THERMAL_GENL_ATTR_CDEV_NAME
#define THERMAL_GENL_ATTR_CDEV_NAME		18
#endif
#ifndef THERMAL_GENL_ATTR_CPU_CAPABILITY
#define THERMAL_GENL_ATTR_CPU_CAPABILITY	20
#endif
#ifndef THERMAL_GENL_ATTR_CPU_CAPABILITY_ID
#define THERMAL_GENL_ATTR_CPU_CAPABILITY_ID	21
#endif
#ifndef THERMAL_GENL_ATTR_CPU_CAPABILITY_PERFORMANCE
#define THERMAL_GENL_ATTR_CPU_CAPABILITY_PERFORMANCE	22
#endif
#ifndef THERMAL_GENL_ATTR_CPU_CAPABILITY_EFFICIENCY
#define THERMAL_GENL_ATTR_CPU_CAPABILITY_EFFICIENCY	23
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

#ifndef THERMAL_GENL_CMD_TZ_GET_ID
#define THERMAL_GENL_CMD_TZ_GET_ID		1
#endif
#ifndef THERMAL_GENL_CMD_TZ_GET_TRIP
#define THERMAL_GENL_CMD_TZ_GET_TRIP		2
#endif
#ifndef THERMAL_GENL_CMD_TZ_GET_TEMP
#define THERMAL_GENL_CMD_TZ_GET_TEMP		3
#endif
#ifndef THERMAL_GENL_CMD_TZ_GET_GOV
#define THERMAL_GENL_CMD_TZ_GET_GOV		4
#endif
#ifndef THERMAL_GENL_CMD_CDEV_GET
#define THERMAL_GENL_CMD_CDEV_GET		6
#endif
#ifndef THERMAL_GENL_CMD_THRESHOLD_GET
#define THERMAL_GENL_CMD_THRESHOLD_GET		7
#endif

static const struct genl_cmd_grammar thermal_cmds[] = {
	{ THERMAL_GENL_CMD_TZ_GET_ID,		"THERMAL_GENL_CMD_TZ_GET_ID" },
	{ THERMAL_GENL_CMD_TZ_GET_TRIP,		"THERMAL_GENL_CMD_TZ_GET_TRIP" },
	{ THERMAL_GENL_CMD_TZ_GET_TEMP,		"THERMAL_GENL_CMD_TZ_GET_TEMP" },
	{ THERMAL_GENL_CMD_TZ_GET_GOV,		"THERMAL_GENL_CMD_TZ_GET_GOV" },
	{ THERMAL_GENL_CMD_CDEV_GET,		"THERMAL_GENL_CMD_CDEV_GET" },
	{ THERMAL_GENL_CMD_THRESHOLD_GET,	"THERMAL_GENL_CMD_THRESHOLD_GET" },
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
 * same way the OVS dp/flow STATS attrs and the L2TP STATS sub-namespace
 * do.  THRESHOLD_TEMP / THRESHOLD_DIRECTION are the per-threshold
 * scalars THRESHOLD_GET enumerates (TEMP in millicelsius, DIRECTION
 * one of THERMAL_THRESHOLD_WAY_UP / WAY_DOWN).  TZ / TZ_TRIP / TZ_GOV /
 * CDEV / CPU_CAPABILITY / THRESHOLD are the six nominally nested
 * containers — emitted as empty NLA_KIND_NESTED placeholders so the
 * kernel's nla_validate accepts them without recursing into a per-sub-
 * policy on the dump-response side.
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
