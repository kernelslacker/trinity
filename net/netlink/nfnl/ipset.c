/*
 * NETLINK_NETFILTER subsystem grammar: ip_set (NFNL_SUBSYS_IPSET), targeting
 * net/netfilter/ipset/ip_set_core.c.  Each command takes the table of its
 * own policy in ip_set_core.c, since the command-level and per-type ids
 * overlap: IPSET_ATTR_DATA is re-parsed strictly against the set type's
 * policies, so its children take the adt_policy ids, and a CREATE's the
 * same plus the create-only sizing ids.  The flat table below is the
 * union the commands fell back to before each had its own.
 */

#include <linux/if.h>
#include <linux/netfilter/nfnetlink.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

#include "kernel/ipset.h"

/* The set name every command carries, so a command can find the set a
 * CREATE made, and the second name a rename takes or a swap looks for. */
static const char ipset_word[] = "trinity";
static const char ipset_word2[] = "trinity2";

/*
 * The children of IPSET_ATTR_DATA, from the set types' adt_policy ids,
 * and of IPSET_ATTR_ADT, which holds DATA nests.  The ids a type reads
 * inside DATA are its own: the CADT ids every type shares, the
 * counter/comment/skb ones most read, and the ones only one type reads
 * (ETHER for hash:mac, NAME for list:set, the second address for the
 * two-address hashes).  A CREATE's DATA takes the ids the create
 * policies read, the CADT ids some of them take and the sizing ones.
 * The two namespaces reuse the same numbers, so neither table holds
 * the other's ids.
 */
static const struct nla_attr_spec ipset_data_attrs[] = {
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
	{ IPSET_ATTR_ETHER,       NLA_KIND_BINARY, 6 },
	{ IPSET_ATTR_NAME,        NLA_KIND_STRING, IPSET_MAXNAMELEN - 1 },
	{ IPSET_ATTR_NAMEREF,     NLA_KIND_STRING, IPSET_MAXNAMELEN - 1 },
	{ IPSET_ATTR_IP2,         NLA_KIND_NESTED, 0 },
	{ IPSET_ATTR_CIDR2,       NLA_KIND_U8,     1 },
	{ IPSET_ATTR_IP2_TO,      NLA_KIND_NESTED, 0 },
	{ IPSET_ATTR_IFACE,       NLA_KIND_STRING, IFNAMSIZ - 1 },
	{ IPSET_ATTR_BYTES,       NLA_KIND_U64,    8 },
	{ IPSET_ATTR_PACKETS,     NLA_KIND_U64,    8 },
	{ IPSET_ATTR_COMMENT,     NLA_KIND_STRING, IPSET_MAX_COMMENT_SIZE },
	{ IPSET_ATTR_SKBMARK,     NLA_KIND_U64,    8 },
	{ IPSET_ATTR_SKBPRIO,     NLA_KIND_U32,    4 },
	{ IPSET_ATTR_SKBQUEUE,    NLA_KIND_U16,    2 },
};

static const struct nla_attr_spec ipset_create_data_attrs[] = {
	{ IPSET_ATTR_IP,          NLA_KIND_NESTED, 0 },
	{ IPSET_ATTR_IP_TO,       NLA_KIND_NESTED, 0 },
	{ IPSET_ATTR_CIDR,        NLA_KIND_U8,     1 },
	{ IPSET_ATTR_PORT,        NLA_KIND_U16,    2 },
	{ IPSET_ATTR_PORT_TO,     NLA_KIND_U16,    2 },
	{ IPSET_ATTR_TIMEOUT,     NLA_KIND_U32,    4 },
	{ IPSET_ATTR_PROTO,       NLA_KIND_U8,     1 },
	{ IPSET_ATTR_CADT_FLAGS,  NLA_KIND_U32,    4 },
	{ IPSET_ATTR_BITMASK,     NLA_KIND_NESTED, 0 },
	{ IPSET_ATTR_INITVAL,     NLA_KIND_U32,    4 },
	{ IPSET_ATTR_HASHSIZE,    NLA_KIND_U32,    4 },
	{ IPSET_ATTR_MAXELEM,     NLA_KIND_U32,    4 },
	{ IPSET_ATTR_NETMASK,     NLA_KIND_U8,     1 },
	{ IPSET_ATTR_BUCKETSIZE,  NLA_KIND_U8,     1 },
	{ IPSET_ATTR_RESIZE,      NLA_KIND_U8,     1 },
	{ IPSET_ATTR_SIZE,        NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec ipset_adt_attrs[] = {
	{ IPSET_ATTR_DATA,        NLA_KIND_NESTED, 0, 0,
	  ipset_data_attrs, ARRAY_SIZE(ipset_data_attrs) },
};

/*
 * The per-command tables, from the policies in ip_set_core.c.  The
 * protocol is at least IPSET_PROTOCOL_MIN where a handler checks a
 * minimum, and exactly IPSET_PROTOCOL where it compares it.  CREATE
 * answers -EINVAL without the protocol, the name, the type name, the
 * revision or the family; ADD and DEL without the protocol, the name
 * or exactly one of DATA and ADT, which no mark says, and TEST without
 * the protocol, the name or DATA.  A set-name command needs the
 * protocol alone, a header or a lookup by name the name as well, a
 * rename or a swap both names, and a lookup by index the protocol and
 * the index.
 */
static const struct nla_attr_spec ipset_protocol_attrs[] = {
	{ IPSET_ATTR_PROTOCOL,    NLA_KIND_U8_RANGE, IPSET_PROTOCOL,
	  IPSET_PROTOCOL, .required = true },
};

static const struct nla_attr_spec ipset_create_attrs[] = {
	{ IPSET_ATTR_PROTOCOL,    NLA_KIND_U8_RANGE, 255,
	  IPSET_PROTOCOL_MIN, .required = true },
	{ IPSET_ATTR_SETNAME,     NLA_KIND_STRING_WORD, 0, 0,
	  .word = ipset_word, .required = true },
	{ IPSET_ATTR_TYPENAME,    NLA_KIND_STRING, IPSET_MAXNAMELEN - 1,
	  .required = true },
	{ IPSET_ATTR_REVISION,    NLA_KIND_U8_RANGE, IPSET_REVISION_MAX, 0,
	  .required = true },
	{ IPSET_ATTR_FAMILY,      NLA_KIND_U8,     1, .required = true },
	{ IPSET_ATTR_DATA,        NLA_KIND_NESTED, 0, 0,
	  ipset_create_data_attrs, ARRAY_SIZE(ipset_create_data_attrs) },
};

static const struct nla_attr_spec ipset_setname_attrs[] = {
	{ IPSET_ATTR_PROTOCOL,    NLA_KIND_U8_RANGE, 255,
	  IPSET_PROTOCOL_MIN, .required = true },
	{ IPSET_ATTR_SETNAME,     NLA_KIND_STRING_WORD, 0, 0,
	  .word = ipset_word },
};

static const struct nla_attr_spec ipset_setname_req_attrs[] = {
	{ IPSET_ATTR_PROTOCOL,    NLA_KIND_U8_RANGE, 255,
	  IPSET_PROTOCOL_MIN, .required = true },
	{ IPSET_ATTR_SETNAME,     NLA_KIND_STRING_WORD, 0, 0,
	  .word = ipset_word, .required = true },
};

static const struct nla_attr_spec ipset_setname2_attrs[] = {
	{ IPSET_ATTR_PROTOCOL,    NLA_KIND_U8_RANGE, 255,
	  IPSET_PROTOCOL_MIN, .required = true },
	{ IPSET_ATTR_SETNAME,     NLA_KIND_STRING_WORD, 0, 0,
	  .word = ipset_word, .required = true },
	{ IPSET_ATTR_SETNAME2,    NLA_KIND_STRING_WORD, 0, 0,
	  .word = ipset_word2, .required = true },
};

static const struct nla_attr_spec ipset_dump_attrs[] = {
	{ IPSET_ATTR_PROTOCOL,    NLA_KIND_U8_RANGE, 255,
	  IPSET_PROTOCOL_MIN, .required = true },
	{ IPSET_ATTR_SETNAME,     NLA_KIND_STRING_WORD, 0, 0,
	  .word = ipset_word },
	{ IPSET_ATTR_FLAGS,       NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec ipset_adt_cmd_attrs[] = {
	{ IPSET_ATTR_PROTOCOL,    NLA_KIND_U8_RANGE, 255,
	  IPSET_PROTOCOL_MIN, .required = true },
	{ IPSET_ATTR_SETNAME,     NLA_KIND_STRING_WORD, 0, 0,
	  .word = ipset_word, .required = true },
	{ IPSET_ATTR_LINENO,      NLA_KIND_U32,    4 },
	{ IPSET_ATTR_DATA,        NLA_KIND_NESTED, 0, 0,
	  ipset_data_attrs, ARRAY_SIZE(ipset_data_attrs) },
	{ IPSET_ATTR_ADT,         NLA_KIND_NESTED, 0, 0,
	  ipset_adt_attrs, ARRAY_SIZE(ipset_adt_attrs) },
};

static const struct nla_attr_spec ipset_test_attrs[] = {
	{ IPSET_ATTR_PROTOCOL,    NLA_KIND_U8_RANGE, 255,
	  IPSET_PROTOCOL_MIN, .required = true },
	{ IPSET_ATTR_SETNAME,     NLA_KIND_STRING_WORD, 0, 0,
	  .word = ipset_word, .required = true },
	{ IPSET_ATTR_DATA,        NLA_KIND_NESTED, 0, 0,
	  ipset_data_attrs, ARRAY_SIZE(ipset_data_attrs), .required = true },
};

static const struct nla_attr_spec ipset_type_attrs[] = {
	{ IPSET_ATTR_PROTOCOL,    NLA_KIND_U8_RANGE, 255,
	  IPSET_PROTOCOL_MIN, .required = true },
	{ IPSET_ATTR_TYPENAME,    NLA_KIND_STRING, IPSET_MAXNAMELEN - 1,
	  .required = true },
	{ IPSET_ATTR_FAMILY,      NLA_KIND_U8,     1, .required = true },
};

static const struct nla_attr_spec ipset_byindex_attrs[] = {
	{ IPSET_ATTR_PROTOCOL,    NLA_KIND_U8_RANGE, IPSET_PROTOCOL,
	  IPSET_PROTOCOL, .required = true },
	{ IPSET_ATTR_INDEX,       NLA_KIND_U16,    2, .required = true },
};

static const struct nfnl_cmd_grammar ipset_cmds[] = {
	{ IPSET_CMD_PROTOCOL,    "IPSET_CMD_PROTOCOL", false,
	  ipset_protocol_attrs, ARRAY_SIZE(ipset_protocol_attrs) },
	{ IPSET_CMD_CREATE,      "IPSET_CMD_CREATE", false,
	  ipset_create_attrs, ARRAY_SIZE(ipset_create_attrs) },
	{ IPSET_CMD_DESTROY,     "IPSET_CMD_DESTROY", false,
	  ipset_setname_attrs, ARRAY_SIZE(ipset_setname_attrs) },
	{ IPSET_CMD_FLUSH,       "IPSET_CMD_FLUSH", false,
	  ipset_setname_attrs, ARRAY_SIZE(ipset_setname_attrs) },
	{ IPSET_CMD_RENAME,      "IPSET_CMD_RENAME", false,
	  ipset_setname2_attrs, ARRAY_SIZE(ipset_setname2_attrs) },
	{ IPSET_CMD_SWAP,        "IPSET_CMD_SWAP", false,
	  ipset_setname2_attrs, ARRAY_SIZE(ipset_setname2_attrs) },
	{ IPSET_CMD_LIST,        "IPSET_CMD_LIST", false,
	  ipset_dump_attrs, ARRAY_SIZE(ipset_dump_attrs) },
	{ IPSET_CMD_SAVE,        "IPSET_CMD_SAVE", false,
	  ipset_setname_attrs, ARRAY_SIZE(ipset_setname_attrs) },
	{ IPSET_CMD_ADD,         "IPSET_CMD_ADD", false,
	  ipset_adt_cmd_attrs, ARRAY_SIZE(ipset_adt_cmd_attrs) },
	{ IPSET_CMD_DEL,         "IPSET_CMD_DEL", false,
	  ipset_adt_cmd_attrs, ARRAY_SIZE(ipset_adt_cmd_attrs) },
	{ IPSET_CMD_TEST,        "IPSET_CMD_TEST", false,
	  ipset_test_attrs, ARRAY_SIZE(ipset_test_attrs) },
	{ IPSET_CMD_HEADER,      "IPSET_CMD_HEADER", false,
	  ipset_setname_req_attrs, ARRAY_SIZE(ipset_setname_req_attrs) },
	{ IPSET_CMD_TYPE,        "IPSET_CMD_TYPE", false,
	  ipset_type_attrs, ARRAY_SIZE(ipset_type_attrs) },
	{ IPSET_CMD_GET_BYNAME,  "IPSET_CMD_GET_BYNAME", false,
	  ipset_setname_req_attrs, ARRAY_SIZE(ipset_setname_req_attrs) },
	{ IPSET_CMD_GET_BYINDEX, "IPSET_CMD_GET_BYINDEX", false,
	  ipset_byindex_attrs, ARRAY_SIZE(ipset_byindex_attrs) },
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
	{ IPSET_ATTR_PROTOCOL,    NLA_KIND_U8_RANGE, 255,
	  IPSET_PROTOCOL_MIN },
	{ IPSET_ATTR_SETNAME,     NLA_KIND_STRING_WORD, 0, 0,
	  .word = ipset_word },
	{ IPSET_ATTR_TYPENAME,    NLA_KIND_STRING, IPSET_MAXNAMELEN - 1 },
	{ IPSET_ATTR_REVISION,    NLA_KIND_U8_RANGE, IPSET_REVISION_MAX, 0 },
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
