/*
 * Genetlink family grammar: dpll (Digital PLL subsystem).
 *
 * The dpll subsystem exposes its userspace control plane through a
 * single generic-netlink family ("dpll") covering device enumeration
 * (DEVICE_ID_GET / DEVICE_GET), per-device configuration (DEVICE_SET),
 * pin enumeration (PIN_ID_GET / PIN_GET), and per-pin configuration
 * (PIN_SET).  All six user-callable commands carry GENL_ADMIN_PERM
 * (CAP_NET_ADMIN gated), but the per-cmd nla_policy walker runs before
 * the capability check so the validator coverage lands unprivileged --
 * penetrating the family demuxer with a real family_id puts every
 * per-cmd parser plus the device / pin lookup paths directly in the
 * fuzzer's reach.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "dpll", so the per-cmd policy walker plus the device
 * and pin dispatch chains have been routinely cold under generic
 * netlink fuzzing; resolving the family at first NETLINK_GENERIC use
 * lets the message generator address real dpll messages whose
 * attribute shapes plausibly survive the per-cmd policy.
 *
 * The six *_NTF notification command ids (DEVICE_CREATE_NTF,
 * DEVICE_DELETE_NTF, DEVICE_CHANGE_NTF, PIN_CREATE_NTF, PIN_DELETE_NTF,
 * PIN_CHANGE_NTF) are kernel-to-userspace only -- the kernel ops table
 * does not list a .doit or .dumpit handler for them, so the dispatcher
 * rejects them on input.  Listing them in the grammar would only burn
 * fuzz budget on a guaranteed -EOPNOTSUPP fast-reject, so they are
 * omitted.
 *
 * The family is split_ops with two distinct attribute namespaces --
 * the device-level DPLL_A_* enum and the per-pin DPLL_A_PIN_* enum --
 * whose id values overlap starting at 1.  The flat nla_attr_spec
 * table the registry consumes cannot disambiguate overlapping keys, so
 * following the ovpn precedent only the device-level DPLL_A_* surface
 * is enumerated here; the DPLL_A_PIN_* table belongs in a future
 * grammar extension that carries a per-command attribute namespace.
 *
 * The family carries a nonzero declared version
 * (DPLL_FAMILY_VERSION = 1) so the default_version member is
 * initialised -- the kernel's dispatcher doesn't gate on the
 * genlmsghdr.version byte today, but matching the declared family
 * version keeps the message generator honest against any future
 * version-gated dispatch.  hdrsize stays 0: dpll has no family-
 * specific fixed header, attributes follow the genlmsghdr directly.
 *
 * Header gating mirrors the ovpn / nbd families: <linux/dpll.h> is the
 * upstream UAPI header carrying every DPLL_CMD_* / DPLL_A_* enum
 * referenced below.  Build hosts lacking the header silently drop the
 * family from the registry instead of failing the build.
 *
 * arch.h is included unconditionally above the __has_include guard so
 * the translation unit is never empty even on build hosts whose uapi
 * lacks <linux/dpll.h> -- the toolchain emits no compile-unit-empty
 * warning and the registry-side ifdef'd extern stays consistent with
 * the absent strong symbol.
 */

#include "arch.h"

#if __has_include(<linux/dpll.h>)

#include <linux/dpll.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * dpll exposes six user-callable commands across two object classes:
 * a three-command device surface (DEVICE_ID_GET / DEVICE_GET /
 * DEVICE_SET) and a three-command pin surface (PIN_ID_GET / PIN_GET /
 * PIN_SET).  All six are GENL_ADMIN_PERM but the nla_policy walker
 * runs before the capability check, so listing all six ids exercises
 * every per-cmd parser symmetrically under the unprivileged fuzzer.
 * The six *_NTF notification ids are kernel-to-userspace only and the
 * dispatcher rejects them on input -- they are omitted by design.
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
 * emits for u64 alignment and is listed so the validator's "ignore on
 * input" branch is exercised the same way the fou / ovpn grammars do.
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
