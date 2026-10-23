/*
 * Genetlink family grammar: ioam6 (IPv6 In-situ OAM, RFC 9197), targeting
 * net/ipv6/ioam6.c.  All seven ops are GENL_ADMIN_PERM.  One flat
 * IOAM6_ATTR_* namespace, no nested containers.
 */

#if __has_include(<linux/ioam6_genl.h>)

#include "kernel/ioam6_genl.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar ioam6_cmds[] = {
	{ IOAM6_CMD_ADD_NAMESPACE,	"IOAM6_CMD_ADD_NAMESPACE" },
	{ IOAM6_CMD_DEL_NAMESPACE,	"IOAM6_CMD_DEL_NAMESPACE" },
	{ IOAM6_CMD_DUMP_NAMESPACES,	"IOAM6_CMD_DUMP_NAMESPACES" },
	{ IOAM6_CMD_ADD_SCHEMA,		"IOAM6_CMD_ADD_SCHEMA" },
	{ IOAM6_CMD_DEL_SCHEMA,		"IOAM6_CMD_DEL_SCHEMA" },
	{ IOAM6_CMD_DUMP_SCHEMAS,	"IOAM6_CMD_DUMP_SCHEMAS" },
	{ IOAM6_CMD_NS_SET_SCHEMA,	"IOAM6_CMD_NS_SET_SCHEMA" },
};

/*
 * Attribute spec follows the IOAM6_ATTR_* enum in <linux/ioam6_genl.h>.
 * NS_ID is a u16 namespace selector keying the per-net namespace map
 * the kernel maintains for inserted IOAM trace data.  NS_DATA and
 * NS_DATA_WIDE are the u32 / u64 option-data scalars the IOAM
 * encapsulating node splices into the IOAM trace option payload when a
 * matching schema is bound; ADD_NAMESPACE accepts both, DUMP echoes
 * them.  SC_ID is the u32 schema-id selector; SC_DATA is the
 * variable-length schema payload (kernel caps at
 * IOAM6_MAX_SCHEMA_DATA_LEN); SC_NONE is the flag attribute used by
 * NS_SET_SCHEMA to clear an existing namespace's schema binding.  PAD
 * is the u64-alignment partner the kernel emits next to NS_DATA_WIDE
 * on dump; listing it lets the generator round-trip what the kernel
 * may parse back.
 */
static const struct nla_attr_spec ioam6_attrs[] = {
	{ IOAM6_ATTR_NS_ID,		NLA_KIND_U16,    2 },
	{ IOAM6_ATTR_NS_DATA,		NLA_KIND_U32,    4 },
	{ IOAM6_ATTR_NS_DATA_WIDE,	NLA_KIND_U64,    8 },
	{ IOAM6_ATTR_SC_ID,		NLA_KIND_U32,    4 },
	{ IOAM6_ATTR_SC_DATA,		NLA_KIND_BINARY, IOAM6_MAX_SCHEMA_DATA_LEN },
	{ IOAM6_ATTR_SC_NONE,		NLA_KIND_FLAG,   0 },
	{ IOAM6_ATTR_PAD,		NLA_KIND_U64,    8 },
};

struct genl_family_grammar fam_ioam6 = {
	.name = "IOAM6",
	.cmds = ioam6_cmds,
	.n_cmds = ARRAY_SIZE(ioam6_cmds),
	.attrs = ioam6_attrs,
	.n_attrs = ARRAY_SIZE(ioam6_attrs),
};

#endif /* __has_include(<linux/ioam6_genl.h>) */
