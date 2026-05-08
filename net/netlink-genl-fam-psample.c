/*
 * Genetlink family grammar: psample (kernel packet sampling).
 *
 * The psample module exposes a single generic-netlink family ("psample")
 * carrying group-state requests and (since 6.10) NEW_GROUP / DEL_GROUP
 * create-delete commands.  PSAMPLE_CMD_SAMPLE is a kernel-to-userspace
 * notification id; userspace can still issue it but the cmd dispatcher
 * rejects it after running the per-cmd nla_policy walker.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "psample", so the per-cmd nla_policy walker in
 * net/psample/psample.c plus the NEW_GROUP / DEL_GROUP create-delete
 * paths have been routinely cold under generic netlink fuzzing;
 * resolving the family at first NETLINK_GENERIC use lets the message
 * generator address real psample messages whose attribute shapes
 * plausibly survive the per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou model, a single
 * flat nla_attr_spec table lists every id used by this family's
 * commands.  psample uses a single flat PSAMPLE_ATTR_* namespace; the
 * one nominally nested attr (PSAMPLE_ATTR_TUNNEL) is emitted as an
 * empty container so the kernel's nla_validate accepts it without
 * recursing into a per-tunnel sub-policy.  The remaining sixteen attrs
 * are scalar / binary / flag covering the group-id / sample-rate
 * selectors, the per-packet metadata (origsize, group seq, latency,
 * timestamp, proto, in/out ifindex, traffic-class occupancy), the
 * sampled-data and user-cookie binary payloads, and the
 * SAMPLE_PROBABILITY presence-only flag added in 6.7.
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

#include <linux/psample.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * Per-symbol shims for PSAMPLE_ATTR_* / PSAMPLE_CMD_* ids.  Build hosts
 * whose <linux/psample.h> predates a given attribute (the post-4.11
 * tunnel / OUT_TC / OUT_TC_OCC, the post-5.13 LATENCY / TIMESTAMP /
 * PROTO triple, the post-6.4 USER_COOKIE, the post-6.7
 * SAMPLE_PROBABILITY flag) silently miss it from the validator
 * coverage; the fallback values match the upstream uapi enum ordering
 * so the wire-format ids the kernel parses match the ones the
 * generator emits.  PSAMPLE_CMD_NEW_GROUP / DEL_GROUP were added in
 * 6.10 and similarly fall back to the upstream enum values.
 */
#ifndef PSAMPLE_ATTR_IIFINDEX
#define PSAMPLE_ATTR_IIFINDEX			0
#endif
#ifndef PSAMPLE_ATTR_OIFINDEX
#define PSAMPLE_ATTR_OIFINDEX			1
#endif
#ifndef PSAMPLE_ATTR_ORIGSIZE
#define PSAMPLE_ATTR_ORIGSIZE			2
#endif
#ifndef PSAMPLE_ATTR_SAMPLE_GROUP
#define PSAMPLE_ATTR_SAMPLE_GROUP		3
#endif
#ifndef PSAMPLE_ATTR_GROUP_SEQ
#define PSAMPLE_ATTR_GROUP_SEQ			4
#endif
#ifndef PSAMPLE_ATTR_SAMPLE_RATE
#define PSAMPLE_ATTR_SAMPLE_RATE		5
#endif
#ifndef PSAMPLE_ATTR_DATA
#define PSAMPLE_ATTR_DATA			6
#endif
#ifndef PSAMPLE_ATTR_GROUP_REFCOUNT
#define PSAMPLE_ATTR_GROUP_REFCOUNT		7
#endif
#ifndef PSAMPLE_ATTR_TUNNEL
#define PSAMPLE_ATTR_TUNNEL			8
#endif
#ifndef PSAMPLE_ATTR_PAD
#define PSAMPLE_ATTR_PAD			9
#endif
#ifndef PSAMPLE_ATTR_OUT_TC
#define PSAMPLE_ATTR_OUT_TC			10
#endif
#ifndef PSAMPLE_ATTR_OUT_TC_OCC
#define PSAMPLE_ATTR_OUT_TC_OCC			11
#endif
#ifndef PSAMPLE_ATTR_LATENCY
#define PSAMPLE_ATTR_LATENCY			12
#endif
#ifndef PSAMPLE_ATTR_TIMESTAMP
#define PSAMPLE_ATTR_TIMESTAMP			13
#endif
#ifndef PSAMPLE_ATTR_PROTO
#define PSAMPLE_ATTR_PROTO			14
#endif
#ifndef PSAMPLE_ATTR_USER_COOKIE
#define PSAMPLE_ATTR_USER_COOKIE		15
#endif
#ifndef PSAMPLE_ATTR_SAMPLE_PROBABILITY
#define PSAMPLE_ATTR_SAMPLE_PROBABILITY		16
#endif

#ifndef PSAMPLE_CMD_SAMPLE
#define PSAMPLE_CMD_SAMPLE			0
#endif
#ifndef PSAMPLE_CMD_GET_GROUP
#define PSAMPLE_CMD_GET_GROUP			1
#endif
#ifndef PSAMPLE_CMD_NEW_GROUP
#define PSAMPLE_CMD_NEW_GROUP			2
#endif
#ifndef PSAMPLE_CMD_DEL_GROUP
#define PSAMPLE_CMD_DEL_GROUP			3
#endif

static const struct genl_cmd_grammar psample_cmds[] = {
	{ PSAMPLE_CMD_GET_GROUP,	"PSAMPLE_CMD_GET_GROUP" },
	{ PSAMPLE_CMD_NEW_GROUP,	"PSAMPLE_CMD_NEW_GROUP" },
	{ PSAMPLE_CMD_DEL_GROUP,	"PSAMPLE_CMD_DEL_GROUP" },
	{ PSAMPLE_CMD_SAMPLE,		"PSAMPLE_CMD_SAMPLE" },
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
 * nominally nested attr — emitted as an empty container so the kernel's
 * nla_validate accepts it without recursing into a per-tunnel
 * sub-policy.  PAD is the alignment partner the kernel emits next to
 * the u64 scalars; it carries no payload, so a 0-byte BINARY entry
 * matches the wire shape.  SAMPLE_PROBABILITY is a presence-only flag.
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
