/*
 * Genetlink family grammar: tcp_metrics (TCP per-destination metric
 * cache).
 *
 * The tcp_metrics core exposes its userspace control plane through a
 * single generic-netlink family ("tcp_metrics") with two user-callable
 * commands: TCP_METRICS_CMD_GET (unprivileged metric query / dump) and
 * TCP_METRICS_CMD_DEL (CAP_NET_ADMIN guarded entry / flush).  Both
 * commands key the per-destination lookup on either ADDR_IPV4 /
 * ADDR_IPV6 (and an optional SADDR_IPV4 / SADDR_IPV6 source-address
 * scoping pair), so the per-cmd nla_policy walker plus the metric
 * cache lookup / removal paths in net/ipv4/tcp_metrics.c are the
 * primary attack surface this family unlocks.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "tcp_metrics", so the per-cmd policy walker plus the
 * GET / DEL dispatch chains have been routinely cold under generic
 * netlink fuzzing; resolving the family at first NETLINK_GENERIC use
 * lets the message generator address real tcp_metrics messages whose
 * attribute shapes plausibly survive the per-cmd policy and land
 * directly in the cache walker where bugs live.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample model,
 * a single flat nla_attr_spec table lists every id used by this
 * family's commands.  tcp_metrics uses a single flat
 * TCP_METRICS_ATTR_* namespace; the one nominally nested attr
 * (TCP_METRICS_ATTR_VALS) is emitted as an empty container so the
 * kernel's nla_validate accepts it without recursing into the
 * per-index sub-policy.  The remaining twelve attrs are scalar /
 * binary covering the IPv4 / IPv6 destination-address key pair, the
 * matching SADDR_IPV4 / SADDR_IPV6 source-address scoping pair, the
 * msecs-age scalar, the TW timestamp pair, the Fast Open MSS / drop
 * count / drop timestamp triple, the Fast Open cookie binary payload,
 * and the response-side PAD alignment partner.
 *
 * The family carries a nonzero declared version (0x1) so the
 * default_version member is initialised — the kernel's GET / DEL
 * dispatchers don't actually gate on the genlmsghdr.version byte
 * today, but matching the declared family version keeps the message
 * generator honest against any future version-gated dispatch.
 *
 * Header gating mirrors the team / hsr / fou / psample / batadv
 * families: <linux/tcp_metrics.h> is the upstream UAPI header
 * carrying every TCP_METRICS_CMD_* and TCP_METRICS_ATTR_* enum
 * referenced below.  Build hosts lacking the header silently drop
 * the family from the registry instead of failing the build.
 * Per-symbol #ifndef shims fill in newer TCP_METRICS_ATTR_* on
 * build hosts whose stale uapi predates the SADDR_IPV4 / SADDR_IPV6
 * source-key additions or the PAD response-side partner.
 *
 * The family is statically linked into the IPv4 core (no separate
 * module to load), so the family_id resolves on every host that
 * runs a stock kernel — no in-fuzz module probing or KO setup
 * required for the grammar to start emitting structured payloads.
 */

#if __has_include(<linux/tcp_metrics.h>)

#include "kernel/tcp_metrics.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * tcp_metrics exposes two user-callable commands: GET is unprivileged
 * (anyone can dump the per-destination metric cache), DEL is
 * CAP_NET_ADMIN gated (entry removal / cache flush).  Both run
 * through the same flat TCP_METRICS_ATTR_* policy; the dispatcher
 * does not branch on a per-cmd policy subset, so listing both ids
 * exercises the unprivileged read-path and (when the process holds
 * the cap) the privileged delete-path symmetrically.
 */
static const struct genl_cmd_grammar tcp_metrics_cmds[] = {
	{ TCP_METRICS_CMD_GET,	"TCP_METRICS_CMD_GET" },
	{ TCP_METRICS_CMD_DEL,	"TCP_METRICS_CMD_DEL" },
};

/*
 * Attribute spec follows the TCP_METRICS_ATTR_* enum in
 * <linux/tcp_metrics.h>.  ADDR_IPV4 / SADDR_IPV4 are __be32 IPv4
 * endpoint addresses; ADDR_IPV6 / SADDR_IPV6 are 16-byte IPv6
 * endpoint addresses.  AGE and FOPEN_SYN_DROP_TS are u64 msecs
 * scalars emitted with the NLA_U64 / nla_put_msecs helpers.
 * TW_TSVAL is a u32 scalar carrying the raw received TCP timestamp;
 * TW_TS_STAMP is a signed s32 second-age scalar (wire-encoded as a
 * 4-byte payload).  FOPEN_MSS / FOPEN_SYN_DROPS are u16 scalars
 * (the latter is a Fast Open SYN-drop counter, the former is the
 * cached MSS).  FOPEN_COOKIE is a 4..16 byte Fast Open cookie
 * binary payload; the kernel walker bounds it implicitly via the
 * NLA-length check inside its nla_policy.  VALS is the one
 * nominally nested attr — emitted as an empty container so the
 * kernel's nla_validate accepts it without recursing into the
 * per-metric-index sub-policy.  PAD is the alignment partner the
 * kernel emits next to the u64 scalars on the response side; it
 * carries no payload, so a 0-byte BINARY entry matches the wire
 * shape.
 */
static const struct nla_attr_spec tcp_metrics_attrs[] = {
	{ TCP_METRICS_ATTR_ADDR_IPV4,		NLA_KIND_U32,    4 },
	{ TCP_METRICS_ATTR_ADDR_IPV6,		NLA_KIND_BINARY, 16 },
	{ TCP_METRICS_ATTR_AGE,			NLA_KIND_U64,    8 },
	{ TCP_METRICS_ATTR_TW_TSVAL,		NLA_KIND_U32,    4 },
	{ TCP_METRICS_ATTR_TW_TS_STAMP,		NLA_KIND_U32,    4 },
	{ TCP_METRICS_ATTR_VALS,		NLA_KIND_NESTED, 0 },
	{ TCP_METRICS_ATTR_FOPEN_MSS,		NLA_KIND_U16,    2 },
	{ TCP_METRICS_ATTR_FOPEN_SYN_DROPS,	NLA_KIND_U16,    2 },
	{ TCP_METRICS_ATTR_FOPEN_SYN_DROP_TS,	NLA_KIND_U64,    8 },
	{ TCP_METRICS_ATTR_FOPEN_COOKIE,	NLA_KIND_BINARY, 16 },
	{ TCP_METRICS_ATTR_SADDR_IPV4,		NLA_KIND_U32,    4 },
	{ TCP_METRICS_ATTR_SADDR_IPV6,		NLA_KIND_BINARY, 16 },
	{ TCP_METRICS_ATTR_PAD,			NLA_KIND_BINARY, 0 },
};

struct genl_family_grammar fam_tcp_metrics = {
	.name = TCP_METRICS_GENL_NAME,
	.cmds = tcp_metrics_cmds,
	.n_cmds = ARRAY_SIZE(tcp_metrics_cmds),
	.attrs = tcp_metrics_attrs,
	.n_attrs = ARRAY_SIZE(tcp_metrics_attrs),
	.default_version = TCP_METRICS_GENL_VERSION,
};

#endif /* __has_include(<linux/tcp_metrics.h>) */
