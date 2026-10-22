/*
 * Genetlink family grammar: psample (kernel packet sampling).
 *
 * The psample module exposes a single generic-netlink family ("psample")
 * whose only op is PSAMPLE_CMD_GET_GROUP, an unprivileged dumpit; a
 * request without NLM_F_DUMP finds no doit and is rejected the same
 * way as the ids below.  PSAMPLE_CMD_SAMPLE, NEW_GROUP and DEL_GROUP
 * are kernel-to-userspace ids (multicast sample and group-change
 * notifications; NEW_GROUP also labels the GET_GROUP dump replies):
 * the genl core finds no op for them and rejects them with
 * -EOPNOTSUPP at the command lookup, before any attribute parsing, so
 * the grammar omits them.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "psample", so the group dump in net/psample/psample.c
 * has been routinely cold under generic netlink fuzzing; resolving the
 * family at first NETLINK_GENERIC use lets the message generator
 * address it.  The op declares no attribute policy, so the genl core
 * skips attribute parsing for it and the attribute table below is
 * never walked on input; it mirrors the attributes the kernel emits.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou model, a single
 * flat nla_attr_spec table lists every id the family's messages use.
 * psample uses a single flat PSAMPLE_ATTR_* namespace; the one
 * nominally nested attr (PSAMPLE_ATTR_TUNNEL) is emitted as an empty
 * container.  The remaining sixteen attrs are scalar / binary / flag
 * covering the group-id / sample-rate fields, the per-packet metadata
 * (origsize, group seq, latency, timestamp, proto, in/out ifindex,
 * traffic-class occupancy), the sampled-data and user-cookie binary
 * payloads, and the SAMPLE_PROBABILITY presence-only flag added in
 * 6.7.
 *
 * Header gating mirrors the team / hsr / fou families: <linux/psample.h>
 * is the upstream UAPI header carrying every PSAMPLE_CMD_* and
 * PSAMPLE_ATTR_* enum referenced below.  Build hosts lacking the
 * header silently drop the family from the registry instead of failing
 * the build.  Per-symbol #ifndef shims fill in newer PSAMPLE_ATTR_* on
 * build hosts whose stale uapi predates the tunnel / latency /
 * timestamp / proto / user-cookie / sample-probability additions.
 */

#if __has_include(<linux/psample.h>)

#include "kernel/psample.h"
#include "netlink-genl-families.h"
#include "utils.h"

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
 * blob can't eat the whole netlink buffer.  TUNNEL is the only
 * nominally nested attr — emitted as an empty container.  PAD is the
 * alignment partner the kernel emits next to the u64 scalars; it
 * carries no payload, so a 0-byte BINARY entry matches the wire shape.
 * SAMPLE_PROBABILITY is a presence-only flag.
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
