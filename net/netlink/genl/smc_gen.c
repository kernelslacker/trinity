/*
 * Genetlink family grammar: SMC_GEN_NETLINK (SMC introspection +
 * UEID / SEID / HS-limitation administration).
 *
 * The SMC-R / SMC-D stack carries a second generic-netlink family
 * (SMC_GENL_FAMILY_NAME = "SMC_GEN_NETLINK") alongside the
 * SMC_PNETID PNET-table editor.  SMC_GEN_NETLINK is the read-mostly
 * introspection + EID-administration surface: GET_SYS_INFO dumps the
 * per-host SMC configuration, the GET_LGR_/GET_LINK_/GET_DEV_/
 * GET_STATS/GET_FBACK_STATS pull link-group and device statistics,
 * and a small set of mutators administers the user EID table
 * (ADD_UEID / REMOVE_UEID / FLUSH_UEID), the system EID enable
 * switch (ENABLE_SEID / DISABLE_SEID) and the handshake-limitation
 * switch (ENABLE_HS_LIMITATION / DISABLE_HS_LIMITATION).  All
 * mutators gate on CAP_NET_ADMIN; the per-cmd nla_policy walker
 * runs before the capability check so validator coverage lands
 * unprivileged.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-
 * assigned family_id for "SMC_GEN_NETLINK", so the per-cmd policy
 * walker plus the UEID add / remove / dump parsers have been
 * routinely cold under generic netlink fuzzing; resolving the
 * family at first NETLINK_GENERIC use lets the message generator
 * address real SMC_GEN_NETLINK messages whose attribute shapes
 * plausibly survive the per-cmd policy.
 *
 * Per the fou / psample / gtp / smc_pnetid model, a single flat
 * nla_attr_spec table lists every id the family's commands
 * exercise.  The input-side attribute set is small: ADD_UEID and
 * REMOVE_UEID parse SMC_NLA_EID_TABLE_ENTRY (NUL-terminated EID
 * string, capped at SMC_MAX_EID_LEN = 32 by the kernel policy);
 * SMC_NLA_SEID_ENTRY is the matching string id for the SEID
 * namespace; SMC_NLA_HS_LIMITATION_ENABLED is the u8 toggle
 * exposed by the handshake-limitation policy.  The remaining
 * top-level SMC_GEN_* ids are reply-only nested containers
 * (per-link-group / per-device dumps) and are intentionally
 * omitted -- they have no input policy on the parser side.
 *
 * Header gating mirrors the smc_pnetid family: <linux/smc.h> is
 * the upstream UAPI header carrying every SMC_NETLINK_*,
 * SMC_NLA_* and SMC_GENL_FAMILY_NAME / _VERSION macro referenced
 * below.  Build hosts lacking the header silently drop the
 * family from the registry instead of failing the build.  All
 * referenced ids have been stable since the user-EID landing in
 * 5.11 so no per-symbol fallback shims are required.
 */

#if __has_include(<linux/smc.h>)

#include <linux/smc.h>

#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar smc_gen_cmds[] = {
	{ SMC_NETLINK_GET_SYS_INFO,		"SMC_NETLINK_GET_SYS_INFO" },
	{ SMC_NETLINK_GET_LGR_SMCR,		"SMC_NETLINK_GET_LGR_SMCR" },
	{ SMC_NETLINK_GET_LINK_SMCR,		"SMC_NETLINK_GET_LINK_SMCR" },
	{ SMC_NETLINK_GET_LGR_SMCD,		"SMC_NETLINK_GET_LGR_SMCD" },
	{ SMC_NETLINK_GET_DEV_SMCD,		"SMC_NETLINK_GET_DEV_SMCD" },
	{ SMC_NETLINK_GET_DEV_SMCR,		"SMC_NETLINK_GET_DEV_SMCR" },
	{ SMC_NETLINK_GET_STATS,		"SMC_NETLINK_GET_STATS" },
	{ SMC_NETLINK_GET_FBACK_STATS,		"SMC_NETLINK_GET_FBACK_STATS" },
	{ SMC_NETLINK_DUMP_UEID,		"SMC_NETLINK_DUMP_UEID" },
	{ SMC_NETLINK_ADD_UEID,			"SMC_NETLINK_ADD_UEID" },
	{ SMC_NETLINK_REMOVE_UEID,		"SMC_NETLINK_REMOVE_UEID" },
	{ SMC_NETLINK_FLUSH_UEID,		"SMC_NETLINK_FLUSH_UEID" },
	{ SMC_NETLINK_DUMP_SEID,		"SMC_NETLINK_DUMP_SEID" },
	{ SMC_NETLINK_ENABLE_SEID,		"SMC_NETLINK_ENABLE_SEID" },
	{ SMC_NETLINK_DISABLE_SEID,		"SMC_NETLINK_DISABLE_SEID" },
	{ SMC_NETLINK_DUMP_HS_LIMITATION,	"SMC_NETLINK_DUMP_HS_LIMITATION" },
	{ SMC_NETLINK_ENABLE_HS_LIMITATION,	"SMC_NETLINK_ENABLE_HS_LIMITATION" },
	{ SMC_NETLINK_DISABLE_HS_LIMITATION,	"SMC_NETLINK_DISABLE_HS_LIMITATION" },
};

/*
 * Attribute spec covers the input-side ids exercised by the
 * family's parsers.  SMC_NLA_EID_TABLE_ENTRY is the
 * SMC_MAX_EID_LEN-bounded (32) EID string ADD_UEID / REMOVE_UEID
 * parse; SMC_NLA_SEID_ENTRY is the SEID namespace's matching
 * string id; SMC_NLA_HS_LIMITATION_ENABLED is the u8 toggle
 * exposed by the handshake-limitation policy.  The bounds match
 * the kernel's .len caps so the validator's length-check arm
 * sees both in-range and over-cap payloads.  The remaining
 * SMC_GEN_* top-level ids are reply-only nested containers and
 * have no input policy on the parser side.
 */
static const struct nla_attr_spec smc_gen_attrs[] = {
	{ SMC_NLA_EID_TABLE_ENTRY,	NLA_KIND_STRING, SMC_MAX_EID_LEN },
	{ SMC_NLA_SEID_ENTRY,		NLA_KIND_STRING, SMC_MAX_EID_LEN },
	{ SMC_NLA_HS_LIMITATION_ENABLED, NLA_KIND_U8,    1 },
};

struct genl_family_grammar fam_smc_gen = {
	.name = SMC_GENL_FAMILY_NAME,
	.cmds = smc_gen_cmds,
	.n_cmds = ARRAY_SIZE(smc_gen_cmds),
	.attrs = smc_gen_attrs,
	.n_attrs = ARRAY_SIZE(smc_gen_attrs),
	.default_version = SMC_GENL_FAMILY_VERSION,
};

#endif /* __has_include(<linux/smc.h>) */
