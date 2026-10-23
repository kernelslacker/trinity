/*
 * Genetlink family grammar: psp (PSP Security Protocol), targeting
 * net/psp/psp-nl-gen.c and psp_nl.c.  DEV_SET, KEY_ROTATE, DEV_ASSOC and
 * DEV_DISASSOC are GENL_ADMIN_PERM, the other four ops are not.  One flat
 * table spans the four attribute namespaces.
 */

#include "kernel/psp.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar psp_cmds[] = {
	{ PSP_CMD_DEV_GET,	"PSP_CMD_DEV_GET" },
	{ PSP_CMD_DEV_SET,	"PSP_CMD_DEV_SET" },
	{ PSP_CMD_KEY_ROTATE,	"PSP_CMD_KEY_ROTATE" },
	{ PSP_CMD_RX_ASSOC,	"PSP_CMD_RX_ASSOC" },
	{ PSP_CMD_TX_ASSOC,	"PSP_CMD_TX_ASSOC" },
	{ PSP_CMD_GET_STATS,	"PSP_CMD_GET_STATS" },
	{ PSP_CMD_DEV_ASSOC,	"PSP_CMD_DEV_ASSOC" },
	{ PSP_CMD_DEV_DISASSOC,	"PSP_CMD_DEV_DISASSOC" },
};

/*
 * Attribute spec follows the per-nest enums in <linux/psp.h>.
 * Numeric ids intentionally overlap across the four namespaces, so an
 * id is checked against whichever per-command policy, or KEYS nest, it
 * lands in.  Of the two NESTED entries only TX_KEY is in a policy
 * (psp_tx_assoc_nl_policy, as NLA_POLICY_NESTED(psp_keys_nl_policy));
 * no policy lists RX_KEY, so the kernel rejects it as unsupported.
 */
static const struct nla_attr_spec psp_attrs[] = {
	/* PSP_A_DEV_* -- DEV_GET / DEV_SET selector + reply payload */
	{ PSP_A_DEV_ID,			NLA_KIND_U32,    4 },
	{ PSP_A_DEV_IFINDEX,		NLA_KIND_U32,    4 },
	{ PSP_A_DEV_PSP_VERSIONS_CAP,	NLA_KIND_U32,    4 },
	{ PSP_A_DEV_PSP_VERSIONS_ENA,	NLA_KIND_U32,    4 },

	/* PSP_A_ASSOC_* -- RX_ASSOC / TX_ASSOC request + reply payload */
	{ PSP_A_ASSOC_DEV_ID,		NLA_KIND_U32,    4 },
	{ PSP_A_ASSOC_VERSION,		NLA_KIND_U32,    4 },
	{ PSP_A_ASSOC_RX_KEY,		NLA_KIND_NESTED, 0 },
	{ PSP_A_ASSOC_TX_KEY,		NLA_KIND_NESTED, 0 },
	{ PSP_A_ASSOC_SOCK_FD,		NLA_KIND_U32,    4 },

	/* PSP_A_KEYS_* -- nested under RX_KEY / TX_KEY containers above */
	{ PSP_A_KEYS_KEY,		NLA_KIND_BINARY, 64 },
	{ PSP_A_KEYS_SPI,		NLA_KIND_U32,    4 },

	/* PSP_A_STATS_* -- GET_STATS reply payload (device counters) */
	{ PSP_A_STATS_DEV_ID,		NLA_KIND_U32,    4 },
	{ PSP_A_STATS_KEY_ROTATIONS,	NLA_KIND_U64,    8 },
	{ PSP_A_STATS_STALE_EVENTS,	NLA_KIND_U64,    8 },
	{ PSP_A_STATS_RX_PACKETS,	NLA_KIND_U64,    8 },
	{ PSP_A_STATS_RX_BYTES,		NLA_KIND_U64,    8 },
	{ PSP_A_STATS_RX_AUTH_FAIL,	NLA_KIND_U64,    8 },
	{ PSP_A_STATS_RX_ERROR,		NLA_KIND_U64,    8 },
	{ PSP_A_STATS_RX_BAD,		NLA_KIND_U64,    8 },
	{ PSP_A_STATS_TX_PACKETS,	NLA_KIND_U64,    8 },
	{ PSP_A_STATS_TX_BYTES,		NLA_KIND_U64,    8 },
	{ PSP_A_STATS_TX_ERROR,		NLA_KIND_U64,    8 },
};

struct genl_family_grammar fam_psp = {
	.name = PSP_FAMILY_NAME,
	.cmds = psp_cmds,
	.n_cmds = ARRAY_SIZE(psp_cmds),
	.attrs = psp_attrs,
	.n_attrs = ARRAY_SIZE(psp_attrs),
	.default_version = PSP_FAMILY_VERSION,
};
