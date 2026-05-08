/*
 * Genetlink family grammar: ioam6 (IPv6 In-situ OAM, RFC 9197).
 *
 * The IOAM6 module exposes its userspace control plane through a
 * single generic-netlink family ("IOAM6") with seven user-callable
 * commands split into two object classes: the IOAM namespaces
 * (ADD_NAMESPACE / DEL_NAMESPACE / DUMP_NAMESPACES) and the schemas
 * carrying their option data (ADD_SCHEMA / DEL_SCHEMA / DUMP_SCHEMAS),
 * plus NS_SET_SCHEMA which binds a schema to an existing namespace.
 * Add/Del primarily gate on the per-object id (NS_ID for the
 * namespace half, SC_ID for the schema half); ADD_NAMESPACE also
 * carries the IOAM data scalars (NS_DATA u32 / NS_DATA_WIDE u64) and
 * ADD_SCHEMA carries the variable-length SC_DATA binary blob plus the
 * SC_NONE flag attribute used by NS_SET_SCHEMA to drop a schema
 * binding back to "no schema".
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "IOAM6", so the per-cmd nla_policy walker plus the
 * namespace / schema mutation paths in net/ipv6/ioam6.c have been
 * routinely cold under generic netlink fuzzing; resolving the family
 * at first NETLINK_GENERIC use lets the message generator address
 * real ioam6 messages whose attribute shapes plausibly survive the
 * per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample / ila
 * model, a single flat nla_attr_spec table lists every id used by
 * this family's commands.  IOAM6 uses a single flat IOAM6_ATTR_*
 * namespace (no nested containers), so the table is one of the
 * simpler grammars: an NS_ID u16 selector, an SC_ID u32 selector,
 * the NS_DATA / NS_DATA_WIDE u32 / u64 option-data scalars, the
 * SC_DATA variable-length binary blob (capped at
 * IOAM6_MAX_SCHEMA_DATA_LEN by the kernel policy), the SC_NONE flag,
 * and the PAD u64-alignment partner.
 *
 * Header gating mirrors the psample / fou / hsr / ila families:
 * <linux/ioam6_genl.h> is the upstream UAPI header carrying every
 * IOAM6_CMD_* and IOAM6_ATTR_* enum referenced below.  Build hosts
 * lacking the header silently drop the family from the registry
 * instead of failing the build.  Per-symbol #ifndef shims fill in
 * IOAM6_ATTR_* / IOAM6_CMD_* on build hosts whose stale uapi predates
 * the namespace-vs-schema attribute split.
 */

#if __has_include(<linux/ioam6_genl.h>)

#include <linux/ioam6_genl.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * Per-symbol shims for IOAM6_ATTR_* / IOAM6_CMD_* ids.  Build hosts
 * whose <linux/ioam6_genl.h> predates a given attribute (the post-5.15
 * NS_DATA_WIDE / SC_* schema additions) silently miss it from the
 * validator coverage; the fallback values match the upstream uapi
 * enum ordering so the wire-format ids the kernel parses match the
 * ones the generator emits.
 */
#ifndef IOAM6_ATTR_NS_ID
#define IOAM6_ATTR_NS_ID		1
#endif
#ifndef IOAM6_ATTR_NS_DATA
#define IOAM6_ATTR_NS_DATA		2
#endif
#ifndef IOAM6_ATTR_NS_DATA_WIDE
#define IOAM6_ATTR_NS_DATA_WIDE		3
#endif
#ifndef IOAM6_ATTR_SC_ID
#define IOAM6_ATTR_SC_ID		4
#endif
#ifndef IOAM6_ATTR_SC_DATA
#define IOAM6_ATTR_SC_DATA		5
#endif
#ifndef IOAM6_ATTR_SC_NONE
#define IOAM6_ATTR_SC_NONE		6
#endif
#ifndef IOAM6_ATTR_PAD
#define IOAM6_ATTR_PAD			7
#endif

#ifndef IOAM6_CMD_ADD_NAMESPACE
#define IOAM6_CMD_ADD_NAMESPACE		1
#endif
#ifndef IOAM6_CMD_DEL_NAMESPACE
#define IOAM6_CMD_DEL_NAMESPACE		2
#endif
#ifndef IOAM6_CMD_DUMP_NAMESPACES
#define IOAM6_CMD_DUMP_NAMESPACES	3
#endif
#ifndef IOAM6_CMD_ADD_SCHEMA
#define IOAM6_CMD_ADD_SCHEMA		4
#endif
#ifndef IOAM6_CMD_DEL_SCHEMA
#define IOAM6_CMD_DEL_SCHEMA		5
#endif
#ifndef IOAM6_CMD_DUMP_SCHEMAS
#define IOAM6_CMD_DUMP_SCHEMAS		6
#endif
#ifndef IOAM6_CMD_NS_SET_SCHEMA
#define IOAM6_CMD_NS_SET_SCHEMA		7
#endif

/*
 * IOAM6_MAX_SCHEMA_DATA_LEN is defined inside the IOAM6_ATTR_* enum in
 * the upstream uapi header (255 * 4 = 1020 bytes — the kernel policy
 * cap on SC_DATA blob length).  Provide a fallback so the SC_DATA spec
 * below has a sane upper bound on hosts whose uapi predates the macro.
 */
#ifndef IOAM6_MAX_SCHEMA_DATA_LEN
#define IOAM6_MAX_SCHEMA_DATA_LEN	(255 * 4)
#endif

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
