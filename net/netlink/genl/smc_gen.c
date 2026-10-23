/*
 * Genetlink family grammar: SMC_GEN_NETLINK (SMC introspection and UEID /
 * SEID / handshake-limitation administration), targeting
 * net/smc/smc_netlink.c.  The mutators are GENL_ADMIN_PERM and only
 * ADD_UEID and REMOVE_UEID accept an attribute, the EID string.
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
 * SMC_NLA_EID_TABLE_ENTRY is the SMC_MAX_EID_LEN-bounded (32) EID
 * string that ADD_UEID / REMOVE_UEID parse (smc_gen_ueid_policy), the
 * one attribute any op accepts: the others use smc_gen_nl_policy, whose
 * only entry rejects id 1.  SMC_NLA_SEID_ENTRY (string) and
 * SMC_NLA_HS_LIMITATION_ENABLED (u8) only appear in the DUMP_SEID /
 * DUMP_HS_LIMITATION replies.  The bounds match the kernel's .len caps
 * so the validator's length-check arm sees both in-range and over-cap
 * payloads.  The remaining SMC_GEN_* top-level ids are reply-only
 * nested containers and have no input policy on the parser side.
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
