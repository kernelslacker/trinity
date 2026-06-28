/*
 * Genetlink family grammar: net-shaper (per-netdev HW rate-limiting).
 *
 * The net_shaper family is the modern (6.13+) per-netdev QoS control
 * plane.  It exposes five user-callable commands: CAP_GET / GET to
 * introspect HW capability and read back the running shaper config,
 * and SET / DELETE / GROUP to create-or-update an individual shaper,
 * tear one down, or build a scheduling group.  SET / DELETE / GROUP
 * carry GENL_ADMIN_PERM (CAP_NET_ADMIN); CAP_GET / GET do not.  All
 * five run the per-cmd nla_policy walker before any capability check,
 * so listing every cmd id symmetrically exercises every per-cmd
 * parser under the unprivileged fuzzer — penetrating the family
 * demuxer with a real family_id puts the parsers plus the per-netdev
 * shaper-tree mutation paths directly in the fuzzer's reach.
 *
 * Random nlmsg_type ids essentially never matched the runtime-assigned
 * family_id for "net-shaper", so the per-cmd policy walker plus the
 * shaper-tree dispatch chains have been routinely cold under generic
 * netlink fuzzing; resolving the family at first NETLINK_GENERIC use
 * lets the message generator address real net_shaper messages whose
 * attribute shapes plausibly survive the per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample /
 * tcp_metrics / ovpn model, a single flat nla_attr_spec table lists
 * every id used by this family's commands.  net_shaper's top-level
 * NET_SHAPER_A_* namespace covers the per-shaper scalar set (METRIC
 * u32 enum, BW_MIN / BW_MAX / BURST u64 rate-and-burst triple,
 * PRIORITY / WEIGHT u32 scheduling pair, IFINDEX u32 netdev selector)
 * alongside three nested containers: HANDLE (the per-shaper {SCOPE,
 * ID} key), PARENT (a HANDLE-shaped parent reference used by GROUP),
 * and LEAVES (a multi-attr leaf-info container also carrying nested
 * HANDLE plus PRIORITY / WEIGHT).  Following the psample-TUNNEL and
 * ovpn-PEER/KEYCONF precedent the three nested containers are emitted
 * as empty NLA_KIND_NESTED entries so the kernel's nla_validate
 * accepts them at the outer level without recursing into the per-nest
 * sub-policies.  The inner NET_SHAPER_A_HANDLE_{SCOPE,ID} and
 * NET_SHAPER_A_CAPS_* enums share id 1..N with the top-level
 * NET_SHAPER_A_* namespace and a single flat table cannot
 * disambiguate the overlapping keys; the shim header carries
 * #ifndef-guarded fallbacks for those inner ids for the next reader
 * who extends the grammar to recursive nested emission.
 *
 * The family carries a nonzero declared version
 * (NET_SHAPER_FAMILY_VERSION = 1) so the default_version member is
 * initialised — the kernel's dispatchers don't actually gate on the
 * genlmsghdr.version byte today, but matching the declared family
 * version keeps the message generator honest against any future
 * version-gated dispatch.  hdrsize stays 0: net_shaper has no
 * family-specific fixed header, attributes follow the genlmsghdr
 * directly.
 *
 * Header gating mirrors the team / hsr / fou / psample / batadv /
 * tcp_metrics / ovpn families: <linux/net_shaper.h> is the upstream
 * UAPI header carrying every NET_SHAPER_CMD_* / NET_SHAPER_A_* enum
 * referenced below.  Build hosts lacking the header silently drop the
 * family from the registry instead of failing the build.  Per-symbol
 * #ifndef shims in include/kernel/net_shaper.h fill in
 * NET_SHAPER_CMD_* / NET_SHAPER_A_* on build hosts whose installed
 * uapi predates this family.
 *
 * arch.h is included unconditionally above the __has_include guard so
 * the translation unit is never empty even on build hosts whose uapi
 * lacks <linux/net_shaper.h> — the toolchain emits no
 * compile-unit-empty warning and the registry-side ifdef'd extern
 * stays consistent with the absent strong symbol.
 */

#include "arch.h"

#if __has_include(<linux/net_shaper.h>)

#include "kernel/net_shaper.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * net_shaper exposes five user-callable commands.  SET / DELETE /
 * GROUP are GENL_ADMIN_PERM; CAP_GET / GET are not.  All five run the
 * nla_policy walker before any capability check, so listing every id
 * exercises every per-cmd parser symmetrically under the unprivileged
 * fuzzer.
 */
static const struct genl_cmd_grammar net_shaper_cmds[] = {
	{ NET_SHAPER_CMD_CAP_GET,	"NET_SHAPER_CMD_CAP_GET" },
	{ NET_SHAPER_CMD_GET,		"NET_SHAPER_CMD_GET" },
	{ NET_SHAPER_CMD_SET,		"NET_SHAPER_CMD_SET" },
	{ NET_SHAPER_CMD_DELETE,	"NET_SHAPER_CMD_DELETE" },
	{ NET_SHAPER_CMD_GROUP,		"NET_SHAPER_CMD_GROUP" },
};

/*
 * Attribute spec follows the top-level NET_SHAPER_A_* enum in
 * <linux/net_shaper.h>.  IFINDEX is the u32 netdev selector that
 * every cmd keys on.  METRIC is a u32 enum (BPS / PPS).  BW_MIN /
 * BW_MAX / BURST are u64 rate/burst-size scalars; PRIORITY / WEIGHT
 * are u32 scheduling scalars.  HANDLE, PARENT, and LEAVES are the
 * three nominally nested attrs — emitted as empty containers
 * psample-TUNNEL / ovpn-PEER style so the kernel's nla_validate
 * accepts them at the outer level without recursing into the per-nest
 * sub-policies.  The inner NET_SHAPER_A_HANDLE_{SCOPE,ID} and
 * NET_SHAPER_A_CAPS_* enums share id 1..N with the top-level
 * namespace; the shim header carries #ifndef-guarded fallbacks for
 * those inner ids for the next reader who extends the grammar to
 * recursive nested emission.
 */
static const struct nla_attr_spec net_shaper_attrs[] = {
	{ NET_SHAPER_A_HANDLE,		NLA_KIND_NESTED, 0 },
	{ NET_SHAPER_A_METRIC,		NLA_KIND_U32,    4 },
	{ NET_SHAPER_A_BW_MIN,		NLA_KIND_U64,    8 },
	{ NET_SHAPER_A_BW_MAX,		NLA_KIND_U64,    8 },
	{ NET_SHAPER_A_BURST,		NLA_KIND_U64,    8 },
	{ NET_SHAPER_A_PRIORITY,	NLA_KIND_U32,    4 },
	{ NET_SHAPER_A_WEIGHT,		NLA_KIND_U32,    4 },
	{ NET_SHAPER_A_IFINDEX,		NLA_KIND_U32,    4 },
	{ NET_SHAPER_A_PARENT,		NLA_KIND_NESTED, 0 },
	{ NET_SHAPER_A_LEAVES,		NLA_KIND_NESTED, 0 },
};

struct genl_family_grammar fam_net_shaper = {
	.name = NET_SHAPER_FAMILY_NAME,
	.cmds = net_shaper_cmds,
	.n_cmds = ARRAY_SIZE(net_shaper_cmds),
	.attrs = net_shaper_attrs,
	.n_attrs = ARRAY_SIZE(net_shaper_attrs),
	.default_version = NET_SHAPER_FAMILY_VERSION,
};

#endif /* __has_include(<linux/net_shaper.h>) */
