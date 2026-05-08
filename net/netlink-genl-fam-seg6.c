/*
 * Genetlink family grammar: SEG6 (IPv6 Segment Routing, RFC 8200 / 8754).
 *
 * The IPv6 SR module exposes its userspace control plane through a
 * single generic-netlink family ("SEG6") with four user-callable
 * commands: SEG6_CMD_SETHMAC, SEG6_CMD_DUMPHMAC, SEG6_CMD_SET_TUNSRC,
 * and SEG6_CMD_GET_TUNSRC.  SETHMAC / DUMPHMAC drive the per-net
 * rhashtable of seg6_hmac_info entries (keyed by HMACKEYID, carrying
 * the secret + algid pair); SET_TUNSRC / GET_TUNSRC swap the per-net
 * IPv6 tunnel-source address used by the lwtunnel encap path.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "SEG6", so the per-cmd nla_policy walker in
 * net/ipv6/seg6.c plus the seg6_hmac_info_add / seg6_hmac_info_del
 * insert/delete paths and the atomic tun_src write have been routinely
 * cold under generic netlink fuzzing; resolving the family at first
 * NETLINK_GENERIC use lets the message generator address real SEG6
 * messages whose attribute shapes plausibly survive the per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample model,
 * a single flat nla_attr_spec table lists every id used by this
 * family's commands.  SEG6 uses a single flat SEG6_ATTR_* namespace;
 * the one nominally nested attr (SEG6_ATTR_HMACINFO) is emitted as an
 * empty container so the kernel's nla_validate accepts it without
 * recursing into a per-entry sub-policy on the dump-response side.
 * The remaining six attrs are scalar / binary covering the IPv6
 * destination / tunnel-source address (16-byte in6_addr), the
 * destination-prefix length scalar, the HMAC keyid / secret / secret-
 * length / algid quadruple that SETHMAC keys on, and the dump-side
 * HMACINFO container.
 *
 * Header gating mirrors the team / hsr / fou / psample families:
 * <linux/seg6_genl.h> is the upstream UAPI header carrying every
 * SEG6_CMD_* and SEG6_ATTR_* enum referenced below.  Build hosts
 * lacking the header silently drop the family from the registry
 * instead of failing the build.  Per-symbol #ifndef shims fill in
 * SEG6_ATTR_* / SEG6_CMD_* on build hosts whose stale uapi predates
 * the current enum layout; the fallback values match the upstream
 * uapi enum ordering so the wire-format ids the kernel parses match
 * the ones the generator emits.
 */

#if __has_include(<linux/seg6_genl.h>)

#include <linux/seg6_genl.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * Per-symbol shims for SEG6_ATTR_* / SEG6_CMD_* ids.  Build hosts
 * whose <linux/seg6_genl.h> predates a given attribute or command
 * silently miss it from the validator coverage; the fallback values
 * match the upstream uapi enum ordering so the wire-format ids the
 * kernel parses match the ones the generator emits.
 */
#ifndef SEG6_ATTR_DST
#define SEG6_ATTR_DST			1
#endif
#ifndef SEG6_ATTR_DSTLEN
#define SEG6_ATTR_DSTLEN		2
#endif
#ifndef SEG6_ATTR_HMACKEYID
#define SEG6_ATTR_HMACKEYID		3
#endif
#ifndef SEG6_ATTR_SECRET
#define SEG6_ATTR_SECRET		4
#endif
#ifndef SEG6_ATTR_SECRETLEN
#define SEG6_ATTR_SECRETLEN		5
#endif
#ifndef SEG6_ATTR_ALGID
#define SEG6_ATTR_ALGID			6
#endif
#ifndef SEG6_ATTR_HMACINFO
#define SEG6_ATTR_HMACINFO		7
#endif

#ifndef SEG6_CMD_SETHMAC
#define SEG6_CMD_SETHMAC		1
#endif
#ifndef SEG6_CMD_DUMPHMAC
#define SEG6_CMD_DUMPHMAC		2
#endif
#ifndef SEG6_CMD_SET_TUNSRC
#define SEG6_CMD_SET_TUNSRC		3
#endif
#ifndef SEG6_CMD_GET_TUNSRC
#define SEG6_CMD_GET_TUNSRC		4
#endif

static const struct genl_cmd_grammar seg6_cmds[] = {
	{ SEG6_CMD_SETHMAC,	"SEG6_CMD_SETHMAC" },
	{ SEG6_CMD_DUMPHMAC,	"SEG6_CMD_DUMPHMAC" },
	{ SEG6_CMD_SET_TUNSRC,	"SEG6_CMD_SET_TUNSRC" },
	{ SEG6_CMD_GET_TUNSRC,	"SEG6_CMD_GET_TUNSRC" },
};

/*
 * Attribute spec follows the SEG6_ATTR_* enum in <linux/seg6_genl.h>.
 * DST is a 16-byte IPv6 destination address (the kernel's seg6_genl_
 * policy caps the binary payload at sizeof(struct in6_addr)); SET_TUNSRC
 * keys on it via nla_get_in6_addr() to atomically swap the per-net
 * tun_src.  DSTLEN is a 4-byte prefix-length scalar (the kernel's
 * policy declares it NLA_S32 but the wire size matches NLA_KIND_U32,
 * and the validator's signedness check is byte-pattern only).
 * HMACKEYID is a u32 secret-table key (a zero key is rejected by
 * SETHMAC); SECRETLEN / ALGID are u8 selectors carrying the
 * 1..SEG6_HMAC_SECRET_LEN-byte secret length and the SEG6_HMAC_ALGO_*
 * algorithm id (1=SHA1, 2=SHA256).  SECRET is the variable-length
 * binary payload bounded above at SEG6_HMAC_SECRET_LEN (64) so a
 * single greedy blob can't eat the whole netlink buffer; setting
 * SECRETLEN==0 drops the SECRET requirement and triggers the delete
 * path through seg6_hmac_info_del().  HMACINFO is the only nominally
 * nested attr — emitted as an empty container so the kernel's
 * nla_validate accepts it without recursing into a per-entry sub-
 * policy on the DUMPHMAC response side.
 */
static const struct nla_attr_spec seg6_attrs[] = {
	{ SEG6_ATTR_DST,		NLA_KIND_BINARY, 16 },
	{ SEG6_ATTR_DSTLEN,		NLA_KIND_U32,    4 },
	{ SEG6_ATTR_HMACKEYID,		NLA_KIND_U32,    4 },
	{ SEG6_ATTR_SECRET,		NLA_KIND_BINARY, 64 },
	{ SEG6_ATTR_SECRETLEN,		NLA_KIND_U8,     1 },
	{ SEG6_ATTR_ALGID,		NLA_KIND_U8,     1 },
	{ SEG6_ATTR_HMACINFO,		NLA_KIND_NESTED, 0 },
};

struct genl_family_grammar fam_seg6 = {
	.name = "SEG6",
	.cmds = seg6_cmds,
	.n_cmds = ARRAY_SIZE(seg6_cmds),
	.attrs = seg6_attrs,
	.n_attrs = ARRAY_SIZE(seg6_attrs),
};

#endif /* __has_include(<linux/seg6_genl.h>) */
