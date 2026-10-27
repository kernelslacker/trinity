/*
 * Genetlink family grammar: psp (PSP Security Protocol), targeting
 * net/psp/psp-nl-gen.c and psp_nl.c.  DEV_SET, KEY_ROTATE, DEV_ASSOC and
 * DEV_DISASSOC are GENL_ADMIN_PERM, the other four ops are not.  An op with
 * a policy has a table of its own.
 */

#include "kernel/psp.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * psp_keys_nl_policy, the nest of TX_ASSOC's TX_KEY.  Its KEY takes any
 * length, but psp_nl_parse_key() wants exactly the version's key size, 16
 * bytes for the 128-bit versions and 32 for the 256-bit ones.
 */
static const struct nla_attr_spec psp_keys_attrs[] = {
	{ PSP_A_KEYS_KEY,		NLA_KIND_BINARY_FIXED2, 32, 16 },
	{ PSP_A_KEYS_SPI,		NLA_KIND_U32,    4 },
};

/*
 * The ops validate strictly against a policy of their own, so an id it has
 * no slot for costs an -EINVAL, and every namespace starts at 1: a cmd takes
 * only the ids of its own.  What the replies carry, the version
 * capabilities, the association list, RX_KEY and the counters, is not in a
 * request policy.  NSID is an s32, a device id is at least 1,
 * VERSIONS_ENA a mask of the four versions and VERSION at most 3.
 */
static const struct nla_attr_spec psp_dev_id_attrs[] = {
	{ PSP_A_DEV_ID,			NLA_KIND_U32_RANGE, UINT32_MAX, 1 },
};

static const struct nla_attr_spec psp_dev_set_attrs[] = {
	{ PSP_A_DEV_ID,			NLA_KIND_U32_RANGE, UINT32_MAX, 1 },
	{ PSP_A_DEV_PSP_VERSIONS_ENA,	NLA_KIND_U32_MASK, 0xf },
};

static const struct nla_attr_spec psp_rx_assoc_attrs[] = {
	{ PSP_A_ASSOC_DEV_ID,		NLA_KIND_U32_RANGE, UINT32_MAX, 1 },
	{ PSP_A_ASSOC_VERSION,		NLA_KIND_U32_RANGE, 3, 0 },
	{ PSP_A_ASSOC_SOCK_FD,		NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec psp_tx_assoc_attrs[] = {
	{ PSP_A_ASSOC_DEV_ID,		NLA_KIND_U32_RANGE, UINT32_MAX, 1 },
	{ PSP_A_ASSOC_VERSION,		NLA_KIND_U32_RANGE, 3, 0 },
	{ PSP_A_ASSOC_TX_KEY,		NLA_KIND_NESTED, 0, 0,
	  psp_keys_attrs, ARRAY_SIZE(psp_keys_attrs) },
	{ PSP_A_ASSOC_SOCK_FD,		NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec psp_get_stats_attrs[] = {
	{ PSP_A_STATS_DEV_ID,		NLA_KIND_U32_RANGE, UINT32_MAX, 1 },
};

static const struct nla_attr_spec psp_dev_assoc_attrs[] = {
	{ PSP_A_DEV_ID,			NLA_KIND_U32_RANGE, UINT32_MAX, 1 },
	{ PSP_A_DEV_IFINDEX,		NLA_KIND_U32,    4 },
	{ PSP_A_DEV_NSID,		NLA_KIND_U32,    4 },
};

/*
 * The dumpits of DEV_GET and GET_STATS have no policy, which the genl core
 * gives a reject-all one, so a dump takes no attribute.  DEV_DISASSOC's
 * policy has the slots of DEV_ASSOC's.
 */
static const struct genl_cmd_grammar psp_cmds[] = {
	{ PSP_CMD_DEV_GET,	"PSP_CMD_DEV_GET",
	  psp_dev_id_attrs, ARRAY_SIZE(psp_dev_id_attrs),
	  genl_no_attrs },
	{ PSP_CMD_DEV_SET,	"PSP_CMD_DEV_SET",
	  psp_dev_set_attrs, ARRAY_SIZE(psp_dev_set_attrs) },
	{ PSP_CMD_KEY_ROTATE,	"PSP_CMD_KEY_ROTATE",
	  psp_dev_id_attrs, ARRAY_SIZE(psp_dev_id_attrs) },
	{ PSP_CMD_RX_ASSOC,	"PSP_CMD_RX_ASSOC",
	  psp_rx_assoc_attrs, ARRAY_SIZE(psp_rx_assoc_attrs) },
	{ PSP_CMD_TX_ASSOC,	"PSP_CMD_TX_ASSOC",
	  psp_tx_assoc_attrs, ARRAY_SIZE(psp_tx_assoc_attrs) },
	{ PSP_CMD_GET_STATS,	"PSP_CMD_GET_STATS",
	  psp_get_stats_attrs, ARRAY_SIZE(psp_get_stats_attrs),
	  genl_no_attrs },
	{ PSP_CMD_DEV_ASSOC,	"PSP_CMD_DEV_ASSOC",
	  psp_dev_assoc_attrs, ARRAY_SIZE(psp_dev_assoc_attrs) },
	{ PSP_CMD_DEV_DISASSOC,	"PSP_CMD_DEV_DISASSOC",
	  psp_dev_assoc_attrs, ARRAY_SIZE(psp_dev_assoc_attrs) },
};

struct genl_family_grammar fam_psp = {
	.name = PSP_FAMILY_NAME,
	.cmds = psp_cmds,
	.n_cmds = ARRAY_SIZE(psp_cmds),
	.default_version = PSP_FAMILY_VERSION,
};
