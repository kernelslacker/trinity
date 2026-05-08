/*
 * Genetlink family grammar: ila (Identifier Locator Addressing).
 *
 * The Identifier Locator Addressing module (RFC 8060 SIR / ILA) exposes
 * its userspace control plane through a single generic-netlink family
 * ("ila") with four user-callable commands: ILA_CMD_ADD, ILA_CMD_DEL,
 * ILA_CMD_GET, and ILA_CMD_FLUSH.  ADD and DEL primarily gate on
 * ILA_ATTR_LOCATOR / ILA_ATTR_LOCATOR_MATCH (the SIR-side selector and
 * the translation-table key), ILA_ATTR_IDENTIFIER (the locator-side
 * value to splice in), and the per-entry policy attrs (CSUM_MODE,
 * IDENT_TYPE, HOOK_TYPE, DIR); GET enumerates configured entries and
 * FLUSH purges the per-net translation table.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "ila", so the per-cmd nla_policy walker plus the
 * ADD / DEL / FLUSH translation-table mutation paths in
 * net/ipv6/ila/ila_xlat.c have been routinely cold under generic
 * netlink fuzzing; resolving the family at first NETLINK_GENERIC use
 * lets the message generator address real ila messages whose attribute
 * shapes plausibly survive the per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample model,
 * a single flat nla_attr_spec table lists every id used by this
 * family's commands.  ila uses a single flat ILA_ATTR_* namespace (no
 * nested containers), so the table is one of the simpler grammars:
 * three u64 selectors covering the LOCATOR / IDENTIFIER / LOCATOR_MATCH
 * triple, an IFINDEX scoping selector, the DIR bitmask, the PAD
 * alignment partner, and three u8 policy selectors (CSUM_MODE,
 * IDENT_TYPE, HOOK_TYPE).
 *
 * Header gating mirrors the psample / fou / hsr families: <linux/ila.h>
 * is the upstream UAPI header carrying every ILA_CMD_* and ILA_ATTR_*
 * enum referenced below.  Build hosts lacking the header silently drop
 * the family from the registry instead of failing the build.  Per-symbol
 * #ifndef shims fill in newer ILA_ATTR_* / ILA_CMD_* on build hosts
 * whose stale uapi predates the IDENT_TYPE / HOOK_TYPE additions.
 */

#if __has_include(<linux/ila.h>)

#include <linux/ila.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * Per-symbol shims for ILA_ATTR_* / ILA_CMD_* ids.  Build hosts whose
 * <linux/ila.h> predates a given attribute (the post-4.10 CSUM_MODE,
 * the post-4.18 IDENT_TYPE / HOOK_TYPE pair) silently miss it from the
 * validator coverage; the fallback values match the upstream uapi enum
 * ordering so the wire-format ids the kernel parses match the ones the
 * generator emits.
 */
#ifndef ILA_ATTR_LOCATOR
#define ILA_ATTR_LOCATOR		1
#endif
#ifndef ILA_ATTR_IDENTIFIER
#define ILA_ATTR_IDENTIFIER		2
#endif
#ifndef ILA_ATTR_LOCATOR_MATCH
#define ILA_ATTR_LOCATOR_MATCH		3
#endif
#ifndef ILA_ATTR_IFINDEX
#define ILA_ATTR_IFINDEX		4
#endif
#ifndef ILA_ATTR_DIR
#define ILA_ATTR_DIR			5
#endif
#ifndef ILA_ATTR_PAD
#define ILA_ATTR_PAD			6
#endif
#ifndef ILA_ATTR_CSUM_MODE
#define ILA_ATTR_CSUM_MODE		7
#endif
#ifndef ILA_ATTR_IDENT_TYPE
#define ILA_ATTR_IDENT_TYPE		8
#endif
#ifndef ILA_ATTR_HOOK_TYPE
#define ILA_ATTR_HOOK_TYPE		9
#endif

#ifndef ILA_CMD_ADD
#define ILA_CMD_ADD			1
#endif
#ifndef ILA_CMD_DEL
#define ILA_CMD_DEL			2
#endif
#ifndef ILA_CMD_GET
#define ILA_CMD_GET			3
#endif
#ifndef ILA_CMD_FLUSH
#define ILA_CMD_FLUSH			4
#endif

static const struct genl_cmd_grammar ila_cmds[] = {
	{ ILA_CMD_ADD,		"ILA_CMD_ADD" },
	{ ILA_CMD_DEL,		"ILA_CMD_DEL" },
	{ ILA_CMD_GET,		"ILA_CMD_GET" },
	{ ILA_CMD_FLUSH,	"ILA_CMD_FLUSH" },
};

/*
 * Attribute spec follows the ILA_ATTR_* enum in <linux/ila.h>.  LOCATOR,
 * IDENTIFIER, and LOCATOR_MATCH are u64 SIR / locator / identifier
 * selectors carrying the 64-bit halves of an IPv6 address.  IFINDEX is
 * a u32 netdev scope selector for per-route translation entries (the
 * uapi declares it s32 — emitting it as a four-byte scalar lets the
 * validator see both sign-extensions and the kernel's bad-ifindex
 * rejection path).  DIR is a u32 ILA_DIR_IN / ILA_DIR_OUT bitmask;
 * emitting random four-byte values exercises the unknown-direction
 * rejection branch alongside the in-range pair.  PAD is the alignment
 * partner the kernel emits next to the u64 scalars; it carries no
 * payload, so a 0-byte BINARY entry matches the wire shape.
 * CSUM_MODE, IDENT_TYPE, and HOOK_TYPE are u8 policy selectors
 * (CSUM_MODE in 0..3, IDENT_TYPE in the ATYPE_IID..NONLOCAL_ADDR range
 * plus the USE_FORMAT escape, HOOK_TYPE in ROUTE_OUTPUT/ROUTE_INPUT —
 * listing the full byte range is the validator's job).  The kernel's
 * ila_nl_policy validates a subset of these on input; the remainder
 * are response-side payloads emitted by ILA_CMD_GET.  Listing them all
 * here exercises the validator's "ignore on input" branch the same way
 * the OVS dp/flow STATS attrs and the L2TP STATS sub-namespace do.
 */
static const struct nla_attr_spec ila_attrs[] = {
	{ ILA_ATTR_LOCATOR,		NLA_KIND_U64,    8 },
	{ ILA_ATTR_IDENTIFIER,		NLA_KIND_U64,    8 },
	{ ILA_ATTR_LOCATOR_MATCH,	NLA_KIND_U64,    8 },
	{ ILA_ATTR_IFINDEX,		NLA_KIND_U32,    4 },
	{ ILA_ATTR_DIR,			NLA_KIND_U32,    4 },
	{ ILA_ATTR_PAD,			NLA_KIND_BINARY, 0 },
	{ ILA_ATTR_CSUM_MODE,		NLA_KIND_U8,     1 },
	{ ILA_ATTR_IDENT_TYPE,		NLA_KIND_U8,     1 },
	{ ILA_ATTR_HOOK_TYPE,		NLA_KIND_U8,     1 },
};

struct genl_family_grammar fam_ila = {
	.name = "ila",
	.cmds = ila_cmds,
	.n_cmds = ARRAY_SIZE(ila_cmds),
	.attrs = ila_attrs,
	.n_attrs = ARRAY_SIZE(ila_attrs),
};

#endif /* __has_include(<linux/ila.h>) */
