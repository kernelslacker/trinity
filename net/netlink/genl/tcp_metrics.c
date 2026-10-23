/*
 * Genetlink family grammar: tcp_metrics (TCP per-destination metric cache),
 * targeting tcp_metrics_nl_policy and the GET / DEL handlers in
 * net/ipv4/tcp_metrics.c.  One flat TCP_METRICS_ATTR_* namespace; the cmd
 * table says which op is privileged.
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
 * NLA-length check inside its nla_policy.  VALS is the one nested
 * attr, which GET replies carry the per-metric values in;
 * tcp_metrics_nl_policy has no entry for it (the line sits under
 * #if 0), so it has no sub-policy on input.  PAD is the alignment
 * partner the kernel emits next to the u64 scalars on the response
 * side; it carries no payload, so a 0-byte BINARY entry matches the
 * wire shape.
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
