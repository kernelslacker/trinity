/*
 * Genetlink family grammar: dpll (Digital PLL subsystem), targeting
 * drivers/dpll/dpll_nl.c and dpll_netlink.c.  All six ops are
 * GENL_ADMIN_PERM; only the device-level DPLL_A_* namespace is listed.
 */

/* Keeps the TU non-empty when the guard below drops the family. */
#include "arch.h"

#if __has_include(<linux/dpll.h>)

#include "kernel/dpll.h"

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * dpll exposes six user-callable commands across two object classes:
 * a three-command device surface (DEVICE_ID_GET / DEVICE_GET /
 * DEVICE_SET) and a three-command pin surface (PIN_ID_GET / PIN_GET /
 * PIN_SET).  All six are GENL_ADMIN_PERM, which the genl core checks
 * before the nla_policy walker runs, so listing all six ids exercises
 * every per-cmd parser symmetrically for a child that passes that
 * check.  The six *_NTF notification ids are kernel-to-userspace only
 * and the dispatcher rejects them on input -- they are omitted by
 * design.
 */
static const struct genl_cmd_grammar dpll_cmds[] = {
	{ DPLL_CMD_DEVICE_ID_GET,	"DPLL_CMD_DEVICE_ID_GET" },
	{ DPLL_CMD_DEVICE_GET,		"DPLL_CMD_DEVICE_GET" },
	{ DPLL_CMD_DEVICE_SET,		"DPLL_CMD_DEVICE_SET" },
	{ DPLL_CMD_PIN_ID_GET,		"DPLL_CMD_PIN_ID_GET" },
	{ DPLL_CMD_PIN_GET,		"DPLL_CMD_PIN_GET" },
	{ DPLL_CMD_PIN_SET,		"DPLL_CMD_PIN_SET" },
};

/*
 * Attribute spec follows the top-level DPLL_A_* enum in <linux/dpll.h>.
 * ID is a u32 device handle that DEVICE_GET / DEVICE_SET key on;
 * CLOCK_ID is the u64 hardware identifier DEVICE_ID_GET / PIN_ID_GET
 * use for lookup; MODULE_NAME is the driver-module string the same
 * GET paths key on alongside CLOCK_ID.  MODE / MODE_SUPPORTED /
 * LOCK_STATUS / LOCK_STATUS_ERROR / TYPE / CLOCK_QUALITY_LEVEL /
 * PHASE_OFFSET_MONITOR are u32 enum selectors; the kernel's
 * dpll_device_set_nl_policy validates PHASE_OFFSET_MONITOR on input,
 * the remainder are response-side payloads emitted by DEVICE_GET.
 * TEMP is a u32-wire signed temperature reading scaled by
 * DPLL_TEMP_DIVIDER.  PAD is the u8 padding slot the YNL generator
 * emits for u64 alignment.  The ops validate strictly, so each
 * response-side id, PAD included, costs an -EINVAL on every command
 * whose policy has no slot for it.
 *
 * The per-pin DPLL_A_PIN_* enum shares id 1..N with the top-level
 * DPLL_A_* namespace and a single flat table cannot disambiguate the
 * overlapping keys -- it is not enumerated here.  A future grammar
 * extension that carries a per-command attribute namespace is the
 * right home for the PIN_* surface (the PIN_GET / PIN_SET commands
 * are still in the cmds[] table above and will start exercising the
 * pin parsers once the per-command namespace lands).
 */
static const struct nla_attr_spec dpll_attrs[] = {
	{ DPLL_A_ID,			NLA_KIND_U32,    4 },
	{ DPLL_A_MODULE_NAME,		NLA_KIND_STRING, 64 },
	{ DPLL_A_PAD,			NLA_KIND_U8,     1 },
	{ DPLL_A_CLOCK_ID,		NLA_KIND_U64,    8 },
	{ DPLL_A_MODE,			NLA_KIND_U32,    4 },
	{ DPLL_A_MODE_SUPPORTED,	NLA_KIND_U32,    4 },
	{ DPLL_A_LOCK_STATUS,		NLA_KIND_U32,    4 },
	{ DPLL_A_TEMP,			NLA_KIND_U32,    4 },
	{ DPLL_A_TYPE,			NLA_KIND_U32,    4 },
	{ DPLL_A_LOCK_STATUS_ERROR,	NLA_KIND_U32,    4 },
	{ DPLL_A_CLOCK_QUALITY_LEVEL,	NLA_KIND_U32,    4 },
	{ DPLL_A_PHASE_OFFSET_MONITOR,	NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_dpll = {
	.name = DPLL_FAMILY_NAME,
	.cmds = dpll_cmds,
	.n_cmds = ARRAY_SIZE(dpll_cmds),
	.attrs = dpll_attrs,
	.n_attrs = ARRAY_SIZE(dpll_attrs),
	.default_version = DPLL_FAMILY_VERSION,
};

#endif /* __has_include(<linux/dpll.h>) */
