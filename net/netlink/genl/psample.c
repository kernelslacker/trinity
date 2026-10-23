/*
 * Genetlink family grammar: psample (kernel packet sampling), targeting
 * net/psample/psample.c.  Its one op, GET_GROUP, is an unprivileged dump
 * and the family declares no attribute policy, so the genl core skips
 * attribute parsing and the table below is never walked on input; it
 * mirrors the attributes the kernel emits.
 */

#if __has_include(<linux/psample.h>)

#include "kernel/psample.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * SAMPLE, NEW_GROUP and DEL_GROUP are kernel-to-userspace ids, not ops
 * (NEW_GROUP also labels the GET_GROUP dump replies), so they are not
 * listed.  A GET_GROUP request without NLM_F_DUMP finds no doit and is
 * rejected the same way.
 */
static const struct genl_cmd_grammar psample_cmds[] = {
	{ PSAMPLE_CMD_GET_GROUP,	"PSAMPLE_CMD_GET_GROUP" },
};

/*
 * Attribute spec follows the PSAMPLE_ATTR_* enum in <linux/psample.h>.
 * IIFINDEX / OIFINDEX / OUT_TC / PROTO are u16 selectors; ORIGSIZE,
 * SAMPLE_GROUP, GROUP_SEQ, SAMPLE_RATE, and GROUP_REFCOUNT are u32
 * scalars (SAMPLE_GROUP carries a 1..1023 group id and SAMPLE_RATE
 * is the 1..0xffff per-packet sampling divisor).  OUT_TC_OCC,
 * LATENCY, and TIMESTAMP are u64 scalars.  DATA and USER_COOKIE are
 * variable-length binary payloads bounded above so a single greedy
 * blob can't eat the whole netlink buffer.  TUNNEL is the only nested
 * attr.  PAD is the alignment partner the kernel emits next to the u64
 * scalars; it carries no payload, so a 0-byte BINARY entry matches the
 * wire shape.  SAMPLE_PROBABILITY is a presence-only flag.
 */
static const struct nla_attr_spec psample_attrs[] = {
	{ PSAMPLE_ATTR_IIFINDEX,		NLA_KIND_U16,    2 },
	{ PSAMPLE_ATTR_OIFINDEX,		NLA_KIND_U16,    2 },
	{ PSAMPLE_ATTR_ORIGSIZE,		NLA_KIND_U32,    4 },
	{ PSAMPLE_ATTR_SAMPLE_GROUP,		NLA_KIND_U32,    4 },
	{ PSAMPLE_ATTR_GROUP_SEQ,		NLA_KIND_U32,    4 },
	{ PSAMPLE_ATTR_SAMPLE_RATE,		NLA_KIND_U32,    4 },
	{ PSAMPLE_ATTR_DATA,			NLA_KIND_BINARY, 64 },
	{ PSAMPLE_ATTR_GROUP_REFCOUNT,		NLA_KIND_U32,    4 },
	{ PSAMPLE_ATTR_TUNNEL,			NLA_KIND_NESTED, 0 },
	{ PSAMPLE_ATTR_PAD,			NLA_KIND_BINARY, 0 },
	{ PSAMPLE_ATTR_OUT_TC,			NLA_KIND_U16,    2 },
	{ PSAMPLE_ATTR_OUT_TC_OCC,		NLA_KIND_U64,    8 },
	{ PSAMPLE_ATTR_LATENCY,			NLA_KIND_U64,    8 },
	{ PSAMPLE_ATTR_TIMESTAMP,		NLA_KIND_U64,    8 },
	{ PSAMPLE_ATTR_PROTO,			NLA_KIND_U16,    2 },
	{ PSAMPLE_ATTR_USER_COOKIE,		NLA_KIND_BINARY, 64 },
	{ PSAMPLE_ATTR_SAMPLE_PROBABILITY,	NLA_KIND_FLAG,   0 },
};

struct genl_family_grammar fam_psample = {
	.name = "psample",
	.cmds = psample_cmds,
	.n_cmds = ARRAY_SIZE(psample_cmds),
	.attrs = psample_attrs,
	.n_attrs = ARRAY_SIZE(psample_attrs),
};

#endif /* __has_include(<linux/psample.h>) */
