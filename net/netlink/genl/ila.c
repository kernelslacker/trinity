/*
 * Genetlink family grammar: ila (Identifier Locator Addressing), targeting
 * net/ipv6/ila/ila_main.c and ila_xlat.c.  One flat ILA_ATTR_* namespace;
 * ADD, DEL and FLUSH are GENL_ADMIN_PERM, GET is not.
 */

#if __has_include(<linux/ila.h>)

#include "kernel/ila.h"
#include "netlink-genl-families.h"
#include "utils.h"

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
 * the OVS dp/flow STATS attrs do.
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
