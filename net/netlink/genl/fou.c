/*
 * Genetlink family grammar: fou (Foo-over-UDP), targeting net/ipv4/fou_nl.c
 * and fou_core.c.  One flat FOU_ATTR_* namespace; ADD and DEL (both
 * GENL_ADMIN_PERM) key on PORT, AF and IPPROTO, GET lists the ports.
 */

#if __has_include(<linux/fou.h>)

#include "kernel/fou.h"
#include "netlink-genl-families.h"
#include "utils.h"

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
 * same way the OVS dp/flow STATS attrs do.
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
