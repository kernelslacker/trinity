/*
 * Genetlink family grammar: fou (Foo-over-UDP).
 *
 * The Foo-over-UDP module exposes its userspace control plane through
 * a single generic-netlink family ("fou") with three user-callable
 * commands: FOU_CMD_ADD, FOU_CMD_DEL, and FOU_CMD_GET.  ADD and DEL
 * primarily gate on FOU_ATTR_PORT (the UDP receive port), FOU_ATTR_AF
 * (address family), and FOU_ATTR_IPPROTO (the inner-protocol selector,
 * IPPROTO_GUE or IPPROTO_UDP); GET enumerates configured ports.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "fou", so the per-cmd nla_policy walker in
 * net/ipv{4,6}/fou_*.c plus the listener add/delete code paths have
 * been routinely cold under generic netlink fuzzing; resolving the
 * family at first NETLINK_GENERIC use lets the message generator
 * address real fou messages whose attribute shapes plausibly survive
 * the per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr model, a single flat
 * nla_attr_spec table lists every id used by this family's commands.
 * fou uses a single flat FOU_ATTR_* namespace (no nested containers),
 * so the table is simpler than the team / l2tp grammars: eleven
 * scalar / binary attrs covering the port and address-family selectors,
 * the peer / local IPv4 / IPv6 endpoint pair, the encap-type selector,
 * and the optional REMCSUM_NOPARTIAL flag and IFINDEX scoping attrs.
 *
 * Header gating mirrors the team / hsr families: <linux/fou.h> is the
 * upstream UAPI header carrying every FOU_CMD_* and FOU_ATTR_* enum
 * referenced below.  Build hosts lacking the header silently drop the
 * family from the registry instead of failing the build.  Per-symbol
 * #ifndef shims fill in newer FOU_ATTR_* on build hosts whose stale
 * uapi predates REMCSUM_NOPARTIAL / IFINDEX / the peer-side attrs.
 */

#if __has_include(<linux/fou.h>)

#include <linux/fou.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * Per-symbol shims for FOU_ATTR_* / FOU_CMD_* ids.  Build hosts whose
 * <linux/fou.h> predates a given attribute (REMCSUM_NOPARTIAL, the
 * peer-side V4/V6 / PEER_PORT triple, IFINDEX) silently miss it from
 * the validator coverage; the fallback values match the upstream uapi
 * enum ordering so the wire-format ids the kernel parses match the
 * ones the generator emits.
 */
#ifndef FOU_ATTR_PORT
#define FOU_ATTR_PORT			1
#endif
#ifndef FOU_ATTR_AF
#define FOU_ATTR_AF			2
#endif
#ifndef FOU_ATTR_IPPROTO
#define FOU_ATTR_IPPROTO		3
#endif
#ifndef FOU_ATTR_TYPE
#define FOU_ATTR_TYPE			4
#endif
#ifndef FOU_ATTR_REMCSUM_NOPARTIAL
#define FOU_ATTR_REMCSUM_NOPARTIAL	5
#endif
#ifndef FOU_ATTR_LOCAL_V4
#define FOU_ATTR_LOCAL_V4		6
#endif
#ifndef FOU_ATTR_LOCAL_V6
#define FOU_ATTR_LOCAL_V6		7
#endif
#ifndef FOU_ATTR_PEER_V4
#define FOU_ATTR_PEER_V4		8
#endif
#ifndef FOU_ATTR_PEER_V6
#define FOU_ATTR_PEER_V6		9
#endif
#ifndef FOU_ATTR_PEER_PORT
#define FOU_ATTR_PEER_PORT		10
#endif
#ifndef FOU_ATTR_IFINDEX
#define FOU_ATTR_IFINDEX		11
#endif

#ifndef FOU_CMD_ADD
#define FOU_CMD_ADD			1
#endif
#ifndef FOU_CMD_DEL
#define FOU_CMD_DEL			2
#endif
#ifndef FOU_CMD_GET
#define FOU_CMD_GET			3
#endif

static const struct genl_cmd_grammar fou_cmds[] = {
	{ FOU_CMD_ADD,	"FOU_CMD_ADD" },
	{ FOU_CMD_DEL,	"FOU_CMD_DEL" },
	{ FOU_CMD_GET,	"FOU_CMD_GET" },
};

/*
 * Attribute spec follows the FOU_ATTR_* enum in <linux/fou.h>.  PORT
 * and PEER_PORT are __be16 wire-encoded UDP port numbers; AF, IPPROTO,
 * and TYPE are u8 selectors (TYPE in the FOU_ENCAP_DIRECT/GUE range
 * 0..2 — listing both in-range and out-of-range values is the
 * validator's job).  REMCSUM_NOPARTIAL is a presence-only flag.
 * LOCAL_V4 / PEER_V4 are __be32 IPv4 endpoint addresses; LOCAL_V6 /
 * PEER_V6 are 16-byte IPv6 endpoint addresses.  IFINDEX is a u32
 * netdev scope selector for the receive socket.  The kernel's
 * fou_nl_policy validates a subset of these on input; the remainder
 * are response-side payloads emitted by FOU_CMD_GET.  Listing them
 * all here exercises the validator's "ignore on input" branch the
 * same way the OVS dp/flow STATS attrs and the L2TP STATS sub-
 * namespace do.
 */
static const struct nla_attr_spec fou_attrs[] = {
	{ FOU_ATTR_PORT,		NLA_KIND_U16,    2 },
	{ FOU_ATTR_AF,			NLA_KIND_U8,     1 },
	{ FOU_ATTR_IPPROTO,		NLA_KIND_U8,     1 },
	{ FOU_ATTR_TYPE,		NLA_KIND_U8,     1 },
	{ FOU_ATTR_REMCSUM_NOPARTIAL,	NLA_KIND_FLAG,   0 },
	{ FOU_ATTR_LOCAL_V4,		NLA_KIND_U32,    4 },
	{ FOU_ATTR_LOCAL_V6,		NLA_KIND_BINARY, 16 },
	{ FOU_ATTR_PEER_V4,		NLA_KIND_U32,    4 },
	{ FOU_ATTR_PEER_V6,		NLA_KIND_BINARY, 16 },
	{ FOU_ATTR_PEER_PORT,		NLA_KIND_U16,    2 },
	{ FOU_ATTR_IFINDEX,		NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_fou = {
	.name = "fou",
	.cmds = fou_cmds,
	.n_cmds = ARRAY_SIZE(fou_cmds),
	.attrs = fou_attrs,
	.n_attrs = ARRAY_SIZE(fou_attrs),
};

#endif /* __has_include(<linux/fou.h>) */
