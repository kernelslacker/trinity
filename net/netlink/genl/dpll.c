/*
 * Genetlink family grammar: dpll (Digital PLL subsystem), targeting
 * drivers/dpll/dpll_nl.c and dpll_netlink.c.  All six ops are
 * GENL_ADMIN_PERM; each takes a policy of its own, so each a table.
 */

/* Keeps the TU non-empty when the guard below drops the family. */
#include "arch.h"

#if __has_include(<linux/dpll.h>)

#include "kernel/dpll.h"

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * The nests of DPLL_CMD_PIN_SET, from dpll_pin_parent_device_nl_policy,
 * dpll_pin_parent_pin_nl_policy and dpll_reference_sync_nl_policy.  They
 * reuse the DPLL_A_PIN_* ids of the pin itself.  PHASE_OFFSET is an s64,
 * the two fractional offsets NLA_SINT, which takes 4 or 8 bytes.  The
 * enums, DIRECTION, STATE and OPERSTATE, are NLA_POLICY_RANGE(NLA_U32, 1, n);
 * a range is written upper bound first, as the BINARY_FIXED2 sizes are.
 */
static const struct nla_attr_spec dpll_parent_device_attrs[] = {
	{ DPLL_A_PIN_PARENT_ID,			NLA_KIND_U32,    4 },
	{ DPLL_A_PIN_DIRECTION,			NLA_KIND_U32_RANGE, 2, 1 },
	{ DPLL_A_PIN_PRIO,			NLA_KIND_U32,    4 },
	{ DPLL_A_PIN_STATE,			NLA_KIND_U32_RANGE, 3, 1 },
	{ DPLL_A_PIN_OPERSTATE,			NLA_KIND_U32_RANGE, 4, 1 },
	{ DPLL_A_PIN_PHASE_OFFSET,		NLA_KIND_U64,    8 },
	{ DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET,
						NLA_KIND_BINARY_FIXED2, 8, 4 },
	{ DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET_PPT,
						NLA_KIND_BINARY_FIXED2, 8, 4 },
};

static const struct nla_attr_spec dpll_parent_pin_attrs[] = {
	{ DPLL_A_PIN_PARENT_ID,			NLA_KIND_U32,    4 },
	{ DPLL_A_PIN_STATE,			NLA_KIND_U32_RANGE, 3, 1 },
};

static const struct nla_attr_spec dpll_reference_sync_attrs[] = {
	{ DPLL_A_PIN_ID,			NLA_KIND_U32,    4 },
	{ DPLL_A_PIN_STATE,			NLA_KIND_U32_RANGE, 3, 1 },
};

/*
 * The ops validate strictly against dpll_*_nl_policy, so an id a cmd's
 * policy has no slot for costs an -EINVAL; the device and pin namespaces
 * share ids 1 to 14 and each cmd's policy ends at its own last id.  The
 * strings are NLA_NUL_STRING, the ids u32, CLOCK_ID and the frequencies
 * u64.  TYPE, MODE and the pin TYPE are NLA_POLICY_RANGE(NLA_U32, 1, n) and
 * the two monitor switches NLA_POLICY_MAX(NLA_U32, 1).  What the replies
 * carry, the lock status, temperature and the rest, is not in any request
 * policy.
 */
static const struct nla_attr_spec dpll_device_id_get_attrs[] = {
	{ DPLL_A_MODULE_NAME,		NLA_KIND_STRING, 64, 1 },
	{ DPLL_A_CLOCK_ID,		NLA_KIND_U64,    8 },
	{ DPLL_A_TYPE,			NLA_KIND_U32_RANGE, 3, 1 },
};

static const struct nla_attr_spec dpll_device_get_attrs[] = {
	{ DPLL_A_ID,			NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec dpll_device_set_attrs[] = {
	{ DPLL_A_ID,			NLA_KIND_U32,    4 },
	{ DPLL_A_MODE,			NLA_KIND_U32_RANGE, 2, 1 },
	{ DPLL_A_PHASE_OFFSET_MONITOR,	NLA_KIND_U32_RANGE, 1 },
	{ DPLL_A_PHASE_OFFSET_AVG_FACTOR, NLA_KIND_U32,  4 },
	{ DPLL_A_FREQUENCY_MONITOR,	NLA_KIND_U32_RANGE, 1 },
};

static const struct nla_attr_spec dpll_pin_id_get_attrs[] = {
	{ DPLL_A_PIN_MODULE_NAME,	NLA_KIND_STRING, 64, 1 },
	{ DPLL_A_PIN_CLOCK_ID,		NLA_KIND_U64,    8 },
	{ DPLL_A_PIN_BOARD_LABEL,	NLA_KIND_STRING, 64, 1 },
	{ DPLL_A_PIN_PANEL_LABEL,	NLA_KIND_STRING, 64, 1 },
	{ DPLL_A_PIN_PACKAGE_LABEL,	NLA_KIND_STRING, 64, 1 },
	{ DPLL_A_PIN_TYPE,		NLA_KIND_U32_RANGE, 6, 1 },
};

static const struct nla_attr_spec dpll_pin_get_attrs[] = {
	{ DPLL_A_PIN_ID,		NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec dpll_pin_set_attrs[] = {
	{ DPLL_A_PIN_ID,		NLA_KIND_U32,    4 },
	{ DPLL_A_PIN_FREQUENCY,		NLA_KIND_U64,    8 },
	{ DPLL_A_PIN_PARENT_DEVICE,	NLA_KIND_NESTED, 0, 0,
	  dpll_parent_device_attrs, ARRAY_SIZE(dpll_parent_device_attrs) },
	{ DPLL_A_PIN_PARENT_PIN,	NLA_KIND_NESTED, 0, 0,
	  dpll_parent_pin_attrs, ARRAY_SIZE(dpll_parent_pin_attrs) },
	{ DPLL_A_PIN_PHASE_ADJUST,	NLA_KIND_U32,    4 },
	{ DPLL_A_PIN_ESYNC_FREQUENCY,	NLA_KIND_U64,    8 },
	{ DPLL_A_PIN_REFERENCE_SYNC,	NLA_KIND_NESTED, 0, 0,
	  dpll_reference_sync_attrs, ARRAY_SIZE(dpll_reference_sync_attrs) },
};

/*
 * dpll exposes six user-callable commands across two object classes:
 * a three-command device surface (DEVICE_ID_GET / DEVICE_GET /
 * DEVICE_SET) and a three-command pin surface (PIN_ID_GET / PIN_GET /
 * PIN_SET).  All six are GENL_ADMIN_PERM, which the genl core checks
 * before the nla_policy walker runs, so listing all six ids exercises
 * every per-cmd parser symmetrically for a child that passes that
 * check.  DEVICE_GET and PIN_GET have a dumpit with no policy, which the
 * genl core gives a reject-all one, so a dump of either takes nothing.
 * The six *_NTF notification ids are kernel-to-userspace only and the
 * dispatcher rejects them on input -- they are omitted by design.
 */
static const struct genl_cmd_grammar dpll_cmds[] = {
	{ DPLL_CMD_DEVICE_ID_GET,	"DPLL_CMD_DEVICE_ID_GET",
	  dpll_device_id_get_attrs, ARRAY_SIZE(dpll_device_id_get_attrs) },
	{ DPLL_CMD_DEVICE_GET,		"DPLL_CMD_DEVICE_GET",
	  dpll_device_get_attrs, ARRAY_SIZE(dpll_device_get_attrs),
	  genl_no_attrs },
	{ DPLL_CMD_DEVICE_SET,		"DPLL_CMD_DEVICE_SET",
	  dpll_device_set_attrs, ARRAY_SIZE(dpll_device_set_attrs) },
	{ DPLL_CMD_PIN_ID_GET,		"DPLL_CMD_PIN_ID_GET",
	  dpll_pin_id_get_attrs, ARRAY_SIZE(dpll_pin_id_get_attrs) },
	{ DPLL_CMD_PIN_GET,		"DPLL_CMD_PIN_GET",
	  dpll_pin_get_attrs, ARRAY_SIZE(dpll_pin_get_attrs),
	  genl_no_attrs },
	{ DPLL_CMD_PIN_SET,		"DPLL_CMD_PIN_SET",
	  dpll_pin_set_attrs, ARRAY_SIZE(dpll_pin_set_attrs) },
};

struct genl_family_grammar fam_dpll = {
	.name = DPLL_FAMILY_NAME,
	.cmds = dpll_cmds,
	.n_cmds = ARRAY_SIZE(dpll_cmds),
	.default_version = DPLL_FAMILY_VERSION,
};

#endif /* __has_include(<linux/dpll.h>) */
