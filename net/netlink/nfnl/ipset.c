/*
 * NETLINK_NETFILTER subsystem grammar: ip_set (NFNL_SUBSYS_IPSET), targeting
 * net/netfilter/ipset/ip_set_core.c.  IPSET_ATTR_DATA is a bare NLA_NESTED
 * that the handlers re-parse strictly against the set type's policies, so the
 * command-level and per-type ids share one flat table (see ipset_attrs[]).
 */

#include <linux/if.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ipset/ip_set.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

/*
 * Shims for CADT / create-only attrs added after the oldest build
 * host's uapi header.  Values are stable enum slots in
 * <linux/netfilter/ipset/ip_set.h>; the fallbacks are what the
 * kernel has always assigned so an older-header build sees the same
 * on-wire numbers a newer-header build does.  MARK / MARKMASK were
 * added for hash:mark; BITMASK for the bitmask netmask work; INITVAL
 * / BUCKETSIZE reused the long-unused IPSET_ATTR_GC /
 * IPSET_ATTR_PROBES slots.
 */
#ifndef IPSET_ATTR_CADT_LINENO
#define IPSET_ATTR_CADT_LINENO	9
#endif
#ifndef IPSET_ATTR_MARK
#define IPSET_ATTR_MARK		10
#endif
#ifndef IPSET_ATTR_MARKMASK
#define IPSET_ATTR_MARKMASK	11
#endif
#ifndef IPSET_ATTR_BITMASK
#define IPSET_ATTR_BITMASK	12
#endif
#ifndef IPSET_ATTR_INITVAL
#define IPSET_ATTR_INITVAL	17
#endif
#ifndef IPSET_ATTR_BUCKETSIZE
#define IPSET_ATTR_BUCKETSIZE	21
#endif
/*
 * ADT-namespace attrs — share numeric slots with the CREATE-only enum
 * (ETHER=17 collides with INITVAL=17, NAME=18 with HASHSIZE=18, etc.)
 * because the kernel matches by policy per nest, not by global id.
 */
#ifndef IPSET_ATTR_ETHER
#define IPSET_ATTR_ETHER	17
#endif
#ifndef IPSET_ATTR_NAME
#define IPSET_ATTR_NAME		18
#endif
#ifndef IPSET_ATTR_NAMEREF
#define IPSET_ATTR_NAMEREF	19
#endif
#ifndef IPSET_ATTR_IP2
#define IPSET_ATTR_IP2		20
#endif
#ifndef IPSET_ATTR_CIDR2
#define IPSET_ATTR_CIDR2	21
#endif
#ifndef IPSET_ATTR_IP2_TO
#define IPSET_ATTR_IP2_TO	22
#endif
#ifndef IPSET_ATTR_IFACE
#define IPSET_ATTR_IFACE	23
#endif
/* Inner IPSET_ATTR_IPADDR nested block. */
#ifndef IPSET_ATTR_IPADDR_IPV6
#define IPSET_ATTR_IPADDR_IPV6	2
#endif

static const struct nfnl_cmd_grammar ipset_cmds[] = {
	{ IPSET_CMD_PROTOCOL,    "IPSET_CMD_PROTOCOL" },
	{ IPSET_CMD_CREATE,      "IPSET_CMD_CREATE" },
	{ IPSET_CMD_DESTROY,     "IPSET_CMD_DESTROY" },
	{ IPSET_CMD_FLUSH,       "IPSET_CMD_FLUSH" },
	{ IPSET_CMD_RENAME,      "IPSET_CMD_RENAME" },
	{ IPSET_CMD_SWAP,        "IPSET_CMD_SWAP" },
	{ IPSET_CMD_LIST,        "IPSET_CMD_LIST" },
	{ IPSET_CMD_SAVE,        "IPSET_CMD_SAVE" },
	{ IPSET_CMD_ADD,         "IPSET_CMD_ADD" },
	{ IPSET_CMD_DEL,         "IPSET_CMD_DEL" },
	{ IPSET_CMD_TEST,        "IPSET_CMD_TEST" },
	{ IPSET_CMD_HEADER,      "IPSET_CMD_HEADER" },
	{ IPSET_CMD_TYPE,        "IPSET_CMD_TYPE" },
	{ IPSET_CMD_GET_BYNAME,  "IPSET_CMD_GET_BYNAME" },
	{ IPSET_CMD_GET_BYINDEX, "IPSET_CMD_GET_BYINDEX" },
};

/*
 * Command-level ids (1-11, IPSET_ATTR_CMD_MAX) first, then the ids the
 * set-type policies type inside IPSET_ATTR_DATA.  The ranges overlap
 * (IPSET_ATTR_IP and IPSET_ATTR_PROTOCOL are both 1, IPSET_ATTR_PROTO and
 * IPSET_ATTR_DATA both 7), so the emitter picks by position.  The
 * dispatcher's liberal parse skips ids past a command's attr_count; inside
 * DATA the strict parse rejects any child the set type's policy lacks.
 */
static const struct nla_attr_spec ipset_attrs[] = {
	/* Command level (ip_set_core.c). */
	{ IPSET_ATTR_PROTOCOL,    NLA_KIND_U8,     1 },
	{ IPSET_ATTR_SETNAME,     NLA_KIND_STRING, IPSET_MAXNAMELEN - 1 },
	{ IPSET_ATTR_TYPENAME,    NLA_KIND_STRING, IPSET_MAXNAMELEN - 1 },
	{ IPSET_ATTR_REVISION,    NLA_KIND_U8,     1 },
	{ IPSET_ATTR_FAMILY,      NLA_KIND_U8,     1 },
	{ IPSET_ATTR_FLAGS,       NLA_KIND_U32,    4 },
	{ IPSET_ATTR_DATA,        NLA_KIND_NESTED, 0 },
	{ IPSET_ATTR_LINENO,      NLA_KIND_U32,    4 },
	{ IPSET_ATTR_INDEX,       NLA_KIND_U16,    2 },

	/* Nested IPSET_ATTR_DATA payload — CADT attrs shared across
	 * every hash: / bitmap: / list: set type. */
	{ IPSET_ATTR_IP,          NLA_KIND_NESTED, 0 },
	{ IPSET_ATTR_IP_TO,       NLA_KIND_NESTED, 0 },
	{ IPSET_ATTR_CIDR,        NLA_KIND_U8,     1 },
	{ IPSET_ATTR_PORT,        NLA_KIND_U16,    2 },
	{ IPSET_ATTR_PORT_TO,     NLA_KIND_U16,    2 },
	{ IPSET_ATTR_TIMEOUT,     NLA_KIND_U32,    4 },
	{ IPSET_ATTR_PROTO,       NLA_KIND_U8,     1 },
	{ IPSET_ATTR_CADT_FLAGS,  NLA_KIND_U32,    4 },
	{ IPSET_ATTR_CADT_LINENO, NLA_KIND_U32,    4 },
	{ IPSET_ATTR_MARK,        NLA_KIND_U32,    4 },
	{ IPSET_ATTR_MARKMASK,    NLA_KIND_U32,    4 },
	{ IPSET_ATTR_BITMASK,     NLA_KIND_NESTED, 0 },

	/* Create-only sizing attrs (hash: family + bitmap: netmask). */
	{ IPSET_ATTR_INITVAL,     NLA_KIND_U32,    4 },
	{ IPSET_ATTR_HASHSIZE,    NLA_KIND_U32,    4 },
	{ IPSET_ATTR_MAXELEM,     NLA_KIND_U32,    4 },
	{ IPSET_ATTR_NETMASK,     NLA_KIND_U8,     1 },
	{ IPSET_ATTR_BUCKETSIZE,  NLA_KIND_U8,     1 },
	{ IPSET_ATTR_RESIZE,      NLA_KIND_U8,     1 },
	{ IPSET_ATTR_SIZE,        NLA_KIND_U32,    4 },

	/* ADT-only attrs (hash:mac ETHER; list:set NAME/NAMEREF;
	 * hash:net,iface IFACE; hash:net,net IP2/CIDR2/IP2_TO). */
	{ IPSET_ATTR_ETHER,       NLA_KIND_BINARY, 6 },
	{ IPSET_ATTR_NAME,        NLA_KIND_STRING, IPSET_MAXNAMELEN - 1 },
	{ IPSET_ATTR_NAMEREF,     NLA_KIND_STRING, IPSET_MAXNAMELEN - 1 },
	{ IPSET_ATTR_IP2,         NLA_KIND_NESTED, 0 },
	{ IPSET_ATTR_CIDR2,       NLA_KIND_U8,     1 },
	{ IPSET_ATTR_IP2_TO,      NLA_KIND_NESTED, 0 },
	{ IPSET_ATTR_IFACE,       NLA_KIND_STRING, IFNAMSIZ - 1 },

	/* Inner IPSET_ATTR_IP / IP_TO / IP2 / IP2_TO nest — the addr
	 * block that carries IPADDR_IPV4 (already collides with the
	 * outer PROTOCOL slot, id=1) plus the IPv6 counterpart. */
	{ IPSET_ATTR_IPADDR_IPV6, NLA_KIND_BINARY, 16 },
};

struct nfnl_subsys_grammar sub_ipset = {
	.name = "ipset",
	.subsys_id = NFNL_SUBSYS_IPSET,
	.cmds = ipset_cmds,
	.n_cmds = ARRAY_SIZE(ipset_cmds),
	.attrs = ipset_attrs,
	.n_attrs = ARRAY_SIZE(ipset_attrs),
};
