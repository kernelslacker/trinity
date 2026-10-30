/*
 * NETLINK_NETFILTER subsystem grammar: nftables (NFNL_SUBSYS_NFTABLES),
 * targeting net/netfilter/nf_tables_api.c.  nftables_cmds[] lists every
 * callback in nf_tables_cb[], each but NFT_MSG_GETGEN, which reads no
 * attribute, with a table of the attributes its handler reads: the
 * namespaces' attribute ids overlap, so there is no one table that serves
 * them (see the comment above the tables).
 */

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

/*
 * Message-type and attribute shims for build hosts whose uapi
 * linux/netfilter/nf_tables.h predates the setelem / obj /
 * flowtable NEW/DEL variants, the *_RESET dumpers, or the DESTROY*
 * family.  Values track the upstream enum ordering.
 */
#ifndef NFT_MSG_NEWSETELEM
#define NFT_MSG_NEWSETELEM		12
#endif
#ifndef NFT_MSG_GETSETELEM
#define NFT_MSG_GETSETELEM		13
#endif
#ifndef NFT_MSG_DELSETELEM
#define NFT_MSG_DELSETELEM		14
#endif
#ifndef NFT_MSG_NEWOBJ
#define NFT_MSG_NEWOBJ			18
#endif
#ifndef NFT_MSG_DELOBJ
#define NFT_MSG_DELOBJ			20
#endif
#ifndef NFT_MSG_GETOBJ_RESET
#define NFT_MSG_GETOBJ_RESET		21
#endif
#ifndef NFT_MSG_NEWFLOWTABLE
#define NFT_MSG_NEWFLOWTABLE		22
#endif
#ifndef NFT_MSG_DELFLOWTABLE
#define NFT_MSG_DELFLOWTABLE		24
#endif
#ifndef NFT_MSG_GETRULE_RESET
#define NFT_MSG_GETRULE_RESET		25
#endif
#ifndef NFT_MSG_DESTROYTABLE
#define NFT_MSG_DESTROYTABLE		26
#endif
#ifndef NFT_MSG_DESTROYCHAIN
#define NFT_MSG_DESTROYCHAIN		27
#endif
#ifndef NFT_MSG_DESTROYRULE
#define NFT_MSG_DESTROYRULE		28
#endif
#ifndef NFT_MSG_DESTROYSET
#define NFT_MSG_DESTROYSET		29
#endif
#ifndef NFT_MSG_DESTROYSETELEM
#define NFT_MSG_DESTROYSETELEM		30
#endif
#ifndef NFT_MSG_DESTROYOBJ
#define NFT_MSG_DESTROYOBJ		31
#endif
#ifndef NFT_MSG_DESTROYFLOWTABLE
#define NFT_MSG_DESTROYFLOWTABLE	32
#endif
#ifndef NFT_MSG_GETSETELEM_RESET
#define NFT_MSG_GETSETELEM_RESET	33
#endif

#ifndef NFTA_SET_ELEM_KEY
#define NFTA_SET_ELEM_KEY		1
#endif
#ifndef NFTA_SET_ELEM_DATA
#define NFTA_SET_ELEM_DATA		2
#endif
#ifndef NFTA_SET_ELEM_FLAGS
#define NFTA_SET_ELEM_FLAGS		3
#endif
#ifndef NFTA_SET_ELEM_TIMEOUT
#define NFTA_SET_ELEM_TIMEOUT		4
#endif
#ifndef NFTA_SET_ELEM_EXPIRATION
#define NFTA_SET_ELEM_EXPIRATION	5
#endif
#ifndef NFTA_SET_ELEM_USERDATA
#define NFTA_SET_ELEM_USERDATA		6
#endif
#ifndef NFTA_SET_ELEM_EXPR
#define NFTA_SET_ELEM_EXPR		7
#endif
#ifndef NFTA_SET_ELEM_OBJREF
#define NFTA_SET_ELEM_OBJREF		9
#endif
#ifndef NFTA_SET_ELEM_KEY_END
#define NFTA_SET_ELEM_KEY_END		10
#endif
#ifndef NFTA_SET_ELEM_EXPRESSIONS
#define NFTA_SET_ELEM_EXPRESSIONS	11
#endif

#ifndef NFTA_OBJ_TABLE
#define NFTA_OBJ_TABLE			1
#endif
#ifndef NFTA_OBJ_NAME
#define NFTA_OBJ_NAME			2
#endif
#ifndef NFTA_OBJ_TYPE
#define NFTA_OBJ_TYPE			3
#endif
#ifndef NFTA_OBJ_DATA
#define NFTA_OBJ_DATA			4
#endif
#ifndef NFTA_OBJ_USERDATA
#define NFTA_OBJ_USERDATA		8
#endif

#ifndef NFTA_FLOWTABLE_TABLE
#define NFTA_FLOWTABLE_TABLE		1
#endif
#ifndef NFTA_FLOWTABLE_NAME
#define NFTA_FLOWTABLE_NAME		2
#endif
#ifndef NFTA_FLOWTABLE_HOOK
#define NFTA_FLOWTABLE_HOOK		3
#endif
#ifndef NFTA_FLOWTABLE_FLAGS
#define NFTA_FLOWTABLE_FLAGS		7
#endif

/*
 * Every name a command carries to find an object by is this one word.  The
 * table is at id 1 in every namespace, a rule's chain, a set, an object and a
 * flowtable at id 2, and a chain's own name at 3, all NLA_STRING matched by
 * their text (nla_strcmp(), or nla_strscpy() into a hash key), and the
 * namespaces keep apart, so a table, its chain, set, object and flowtable can
 * all carry the same word.  What one command names, a later command of its
 * batch then finds.  The word is fixed rather than drawn per batch, so the
 * next batch names the tables the last one committed instead of piling up new
 * ones; only the draw in eight that is random makes another.
 */
static const char nft_word[] = "trinity";

/* The one device a hook names: lo, which every netns has. */
static const char nft_dev_word[] = "lo";

/*
 * A command draws its attributes from a table of its own, which holds what
 * its handler reads of its namespace's policy.  The namespaces number their
 * attributes from 1 each, so an id means one thing to a table command and
 * another to a chain or a set command, and no one table can serve them all.
 * A table marks .required the attributes its handler returns early without:
 * nft_table_lookup() and its kin answer -EINVAL to a name that is missing, so
 * a request without one never reaches the main path.  The handles are drawn
 * small, from 1 to 64: the kernel numbers tables, chains and the rest itself,
 * one counter per table from 1, so only a small handle names an object an
 * earlier command made, and a handler that is given one looks the object up
 * by it in place of its name.  The transaction ids are left out: a chain, a
 * rule or a set id names only what the same batch gave that id, which no
 * draw knows, and neither do POSITION_ID, which names the rule to insert
 * beside, or CHAIN_ID, which names the chain to add a rule to.
 */

/*
 * The table commands.  NEWTABLE reads the name, the flags and the user data
 * of nft_table_policy and answers -EINVAL without a name; GETTABLE does too,
 * unless it is a dump.  DELTABLE and DESTROYTABLE take a name or a handle,
 * and with neither flush every table of the family, which the name left out
 * of one request in eight still makes them do.
 */
static const struct nla_attr_spec nft_newtable_attrs[] = {
	{ NFTA_TABLE_NAME,     NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_TABLE_FLAGS,    NLA_KIND_BE32_MASK, NFT_TABLE_F_MASK },
	{ NFTA_TABLE_USERDATA, NLA_KIND_BINARY, 64 },
};

static const struct nla_attr_spec nft_gettable_attrs[] = {
	{ NFTA_TABLE_NAME,     NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
};

static const struct nla_attr_spec nft_deltable_attrs[] = {
	{ NFTA_TABLE_NAME,     NLA_KIND_STRING_WORD, 0, 0, .word = nft_word },
	{ NFTA_TABLE_HANDLE,   NLA_KIND_BE64_RANGE, 64, 1 },
};

/*
 * The chain commands.  NEWCHAIN reads the table and the chain's name of
 * nft_chain_policy, and answers -EINVAL if either is missing (a handle may
 * stand in for the name, and an id, which the grammar leaves out); GETCHAIN,
 * DELCHAIN and DESTROYCHAIN need both as well, and read nothing else a request
 * can usefully carry: a delete's HOOK names the devices of a netdev chain, and
 * DESTROYCHAIN answers it -EOPNOTSUPP.
 *
 * NEWCHAIN makes a base chain only if HOOK holds a hook number and a priority
 * (nft_chain_parse_hook() answers -ENOENT unless it has both), and COUNTERS
 * must hold both counters (nft_stats_alloc()), so both nests have tables of
 * their own.  HOOK may also name devices, one DEV or a DEVS nest of device
 * names and prefixes, which nft_chain_parse_netdev() looks up; a name that
 * is none answers -ENODEV.  The number must be below NFT_MAX_HOOKS and in the chain type's
 * hook_mask: the five inet hooks are the ones every IPv4, IPv6 and bridge
 * filter chain has, ARP and netdev chains have fewer, and what they refuse
 * keeps the reject arm in view.  The handlers read the number, the priority
 * and POLICY in network byte order, and POLICY must be NF_DROP or NF_ACCEPT,
 * anything else being -EINVAL.  A TYPE the kernel has no chain type of
 * costs it a request_module() on each such name, so it is one of the three it
 * has.
 */
static const unsigned int nft_hooknums[] = {
	NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD,
	NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING,
};

static const unsigned int nft_policies[] = { NF_DROP, NF_ACCEPT };

static const char *const nft_chain_types[] = { "filter", "nat", "route" };

/*
 * The devices a hook names: nft_tables_parse_netdev_hooks() walks DEVS for
 * NFTA_DEVICE_NAME and NFTA_DEVICE_PREFIX children and looks each up, and
 * nft_chain_parse_netdev() takes one DEV the same way.
 */
static const struct nla_attr_spec nft_device_attrs[] = {
	{ NFTA_DEVICE_NAME,   NLA_KIND_STRING_WORD, 0, 0, .word = nft_dev_word },
	{ NFTA_DEVICE_PREFIX, NLA_KIND_STRING_WORD, 0, 0, .word = nft_dev_word },
};

static const struct nla_attr_spec nft_chain_hook_attrs[] = {
	{ NFTA_HOOK_HOOKNUM,   NLA_KIND_BE32_ONEOF, 0, 0,
	  .oneof = nft_hooknums, .n_oneof = ARRAY_SIZE(nft_hooknums),
	  .required = true },
	{ NFTA_HOOK_PRIORITY,  NLA_KIND_U32, 4, .required = true },
	{ NFTA_HOOK_DEV,       NLA_KIND_STRING_WORD, 0, 0, .word = nft_dev_word },
	{ NFTA_HOOK_DEVS,      NLA_KIND_NESTED, 0, 0,
	  nft_device_attrs, ARRAY_SIZE(nft_device_attrs) },
};

static const struct nla_attr_spec nft_chain_counters_attrs[] = {
	{ NFTA_COUNTER_BYTES,   NLA_KIND_U64, 8, .required = true },
	{ NFTA_COUNTER_PACKETS, NLA_KIND_U64, 8, .required = true },
};

static const struct nla_attr_spec nft_newchain_attrs[] = {
	{ NFTA_CHAIN_TABLE,    NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_CHAIN_HANDLE,   NLA_KIND_BE64_RANGE, 64, 1 },
	{ NFTA_CHAIN_NAME,     NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_CHAIN_HOOK,     NLA_KIND_NESTED, 0, 0,
	  nft_chain_hook_attrs, ARRAY_SIZE(nft_chain_hook_attrs) },
	{ NFTA_CHAIN_POLICY,   NLA_KIND_BE32_ONEOF, 0, 0,
	  .oneof = nft_policies, .n_oneof = ARRAY_SIZE(nft_policies) },
	{ NFTA_CHAIN_TYPE,     NLA_KIND_STRING_ONEOF, 0, 0,
	  .words = nft_chain_types, .n_words = ARRAY_SIZE(nft_chain_types) },
	{ NFTA_CHAIN_COUNTERS, NLA_KIND_NESTED, 0, 0,
	  nft_chain_counters_attrs, ARRAY_SIZE(nft_chain_counters_attrs) },
	{ NFTA_CHAIN_FLAGS,    NLA_KIND_BE32_MASK, NFT_CHAIN_FLAGS },
	{ NFTA_CHAIN_USERDATA, NLA_KIND_BINARY, 64 },
};

static const struct nla_attr_spec nft_chain_name_attrs[] = {
	{ NFTA_CHAIN_TABLE,    NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_CHAIN_HANDLE,   NLA_KIND_BE64_RANGE, 64, 1 },
	{ NFTA_CHAIN_NAME,     NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
};

/*
 * The rule commands.  NEWRULE reads the table and the chain's name of
 * nft_rule_policy, and answers -EINVAL to a request without a table or with
 * neither a chain nor a chain id; it reads the expressions, the user data and
 * the rule's id as well.  GETRULE and GETRULE_RESET need the table and the
 * chain, and a dump takes them as the filters of what it lists.  DELRULE and
 * DESTROYRULE need the table, and without a chain delete the rules of every
 * chain in it.  The handle and POSITION are drawn small: a handle makes
 * NEWRULE replace the rule it names, or answer -EOPNOTSUPP without REPLACE,
 * and POSITION names the rule to insert beside, failing -ENOENT when none
 * matches.  POSITION_ID and CHAIN_ID are left out, as the transaction ids
 * above.  GETRULE then ends in the -EINVAL that asks for the handle when it
 * carries none, and a delete without one deletes the chain's rules, not one.
 * COMPAT is read only by the nft_compat expressions.
 *
 * NFTA_RULE_EXPRESSIONS is a nest with no table of its own.  An element must
 * be of type NFTA_LIST_ELEM and name a registered expression
 * (nf_tables_expr_parse() answers -EINVAL to one without a name), which
 * nothing drawn from this table does, so a NEWRULE that carries the
 * attribute is refused.
 */
static const struct nla_attr_spec nft_newrule_attrs[] = {
	{ NFTA_RULE_TABLE,       NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_RULE_CHAIN,       NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_RULE_HANDLE,      NLA_KIND_BE64_RANGE, 64, 1 },
	{ NFTA_RULE_EXPRESSIONS, NLA_KIND_NESTED, 0 },
	{ NFTA_RULE_POSITION,    NLA_KIND_BE64_RANGE, 64, 1 },
	{ NFTA_RULE_USERDATA,    NLA_KIND_BINARY, 64 },
	{ NFTA_RULE_ID,          NLA_KIND_U32, 4 },
};

static const struct nla_attr_spec nft_getrule_attrs[] = {
	{ NFTA_RULE_TABLE,       NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_RULE_CHAIN,       NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_RULE_HANDLE,      NLA_KIND_BE64_RANGE, 64, 1 },
};

static const struct nla_attr_spec nft_delrule_attrs[] = {
	{ NFTA_RULE_TABLE,       NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_RULE_CHAIN,       NLA_KIND_STRING_WORD, 0, 0, .word = nft_word },
	{ NFTA_RULE_HANDLE,      NLA_KIND_BE64_RANGE, 64, 1 },
};

/*
 * The set commands.  NEWSET answers -EINVAL unless the request holds the
 * table, the name, NFTA_SET_KEY_LEN and the set's id, so all four are marked,
 * and reads the rest of what nft_set_policy lets a set be made from.  It
 * reads the lengths and the policy with ntohl(): KEY_LEN and DATA_LEN must be
 * from 1 to NFT_DATA_VALUE_MAXLEN, or the answer is -EINVAL, and POLICY
 * NFT_SET_POL_PERFORMANCE or NFT_SET_POL_MEMORY, or -EOPNOTSUPP.  Several
 * attributes need another: DATA_TYPE needs the NFT_SET_MAP flag and, unless
 * it is a verdict, a DATA_LEN, TIMEOUT and GC_INTERVAL need NFT_SET_TIMEOUT,
 * OBJ_TYPE NFT_SET_OBJECT, and the grammar does not tie them together.  DESC,
 * EXPR and EXPRESSIONS are nests it cannot build yet, so none of the three is
 * in the table.  GETSET, DELSET and DESTROYSET need the table and the name,
 * or the set's handle, drawn small as the others are; NEWSET never reads the
 * handle, its sets being numbered as they are made.
 */
static const unsigned int nft_set_policies[] = {
	NFT_SET_POL_PERFORMANCE, NFT_SET_POL_MEMORY,
};

static const struct nla_attr_spec nft_newset_attrs[] = {
	{ NFTA_SET_TABLE,     NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_SET_NAME,      NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_SET_FLAGS,     NLA_KIND_BE32_MASK,
		NFT_SET_ANONYMOUS | NFT_SET_CONSTANT | NFT_SET_INTERVAL |
		NFT_SET_MAP | NFT_SET_TIMEOUT | NFT_SET_EVAL | NFT_SET_OBJECT |
		NFT_SET_CONCAT | NFT_SET_EXPR },
	{ NFTA_SET_KEY_TYPE,  NLA_KIND_U32, 4 },
	{ NFTA_SET_KEY_LEN,   NLA_KIND_BE32_RANGE, NFT_DATA_VALUE_MAXLEN, 1,
	  .required = true },
	{ NFTA_SET_DATA_TYPE, NLA_KIND_U32, 4 },
	{ NFTA_SET_DATA_LEN,  NLA_KIND_BE32_RANGE, NFT_DATA_VALUE_MAXLEN, 1 },
	{ NFTA_SET_POLICY,    NLA_KIND_BE32_ONEOF, 0, 0,
	  .oneof = nft_set_policies, .n_oneof = ARRAY_SIZE(nft_set_policies) },
	{ NFTA_SET_ID,        NLA_KIND_U32, 4, .required = true },
	{ NFTA_SET_TIMEOUT,   NLA_KIND_U64, 8 },
	{ NFTA_SET_GC_INTERVAL, NLA_KIND_U32, 4 },
	{ NFTA_SET_USERDATA,  NLA_KIND_BINARY, 64 },
	{ NFTA_SET_OBJ_TYPE,  NLA_KIND_U32, 4 },
};

static const struct nla_attr_spec nft_set_name_attrs[] = {
	{ NFTA_SET_TABLE,     NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_SET_NAME,      NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_SET_HANDLE,    NLA_KIND_BE64_RANGE, 64, 1 },
};

/*
 * The set-element commands.  NEWSETELEM answers -EINVAL without
 * NFTA_SET_ELEM_LIST_ELEMENTS, then without the table, then without the set,
 * for which the set's id can stand in.  GETSETELEM wants the elements unless
 * it is a dump, and then the table and the set; DELSETELEM and
 * DESTROYSETELEM want the table and the set, and without elements empty the
 * set, so theirs are not marked.  Only NEWSETELEM reads the id.
 *
 * ELEMENTS is an NLA_POLICY_NESTED_ARRAY of nft_set_elem_policy.  Adding an
 * element reads all of it and answers -EINVAL to one without a KEY, unless its
 * flags say it is the catch-all; getting and deleting one read the key, the
 * flags and KEY_END, which are what their tables hold.  A key is a nest
 * of nft_data_policy that must hold a VALUE, whose length has to be the set's
 * KEY_LEN, as nft_value_init() sees to; no length is known to the draw, so one
 * element in sixty-four or so gets by.  The DATA, EXPR and EXPRESSIONS of an
 * element are nests the grammar leaves to the table of the element.
 */
static const struct nla_attr_spec nft_set_data_attrs[] = {
	{ NFTA_DATA_VALUE,         NLA_KIND_BINARY, NFT_DATA_VALUE_MAXLEN, 1,
	  .required = true },
};

static const struct nla_attr_spec nft_set_elem_attrs[] = {
	{ NFTA_SET_ELEM_KEY,         NLA_KIND_NESTED, 0, 0,
	  nft_set_data_attrs, ARRAY_SIZE(nft_set_data_attrs), .required = true },
	{ NFTA_SET_ELEM_DATA,        NLA_KIND_NESTED, 0 },
	{ NFTA_SET_ELEM_FLAGS,       NLA_KIND_BE32_MASK,
		NFT_SET_ELEM_INTERVAL_END | NFT_SET_ELEM_CATCHALL },
	{ NFTA_SET_ELEM_TIMEOUT,     NLA_KIND_U64,    8 },
	{ NFTA_SET_ELEM_EXPIRATION,  NLA_KIND_U64,    8 },
	{ NFTA_SET_ELEM_USERDATA,    NLA_KIND_BINARY, 64 },
	{ NFTA_SET_ELEM_EXPR,        NLA_KIND_NESTED, 0 },
	{ NFTA_SET_ELEM_OBJREF,      NLA_KIND_STRING, 32 },
	{ NFTA_SET_ELEM_KEY_END,     NLA_KIND_NESTED, 0, 0,
	  nft_set_data_attrs, ARRAY_SIZE(nft_set_data_attrs) },
	{ NFTA_SET_ELEM_EXPRESSIONS, NLA_KIND_NESTED, 0 },
};

static const struct nla_attr_spec nft_set_elem_key_attrs[] = {
	{ NFTA_SET_ELEM_KEY,         NLA_KIND_NESTED, 0, 0,
	  nft_set_data_attrs, ARRAY_SIZE(nft_set_data_attrs), .required = true },
	{ NFTA_SET_ELEM_FLAGS,       NLA_KIND_BE32_MASK,
		NFT_SET_ELEM_INTERVAL_END | NFT_SET_ELEM_CATCHALL },
	{ NFTA_SET_ELEM_KEY_END,     NLA_KIND_NESTED, 0, 0,
	  nft_set_data_attrs, ARRAY_SIZE(nft_set_data_attrs) },
};

static const struct nla_attr_spec nft_newsetelem_attrs[] = {
	{ NFTA_SET_ELEM_LIST_TABLE,    NLA_KIND_STRING_WORD, 0, 0,
	  .word = nft_word, .required = true },
	{ NFTA_SET_ELEM_LIST_SET,      NLA_KIND_STRING_WORD, 0, 0,
	  .word = nft_word, .required = true },
	{ NFTA_SET_ELEM_LIST_ELEMENTS, NLA_KIND_NESTED_ARRAY, 0, 0,
	  nft_set_elem_attrs, ARRAY_SIZE(nft_set_elem_attrs), .required = true },
	{ NFTA_SET_ELEM_LIST_SET_ID,   NLA_KIND_U32, 4 },
};

static const struct nla_attr_spec nft_getsetelem_attrs[] = {
	{ NFTA_SET_ELEM_LIST_TABLE,    NLA_KIND_STRING_WORD, 0, 0,
	  .word = nft_word, .required = true },
	{ NFTA_SET_ELEM_LIST_SET,      NLA_KIND_STRING_WORD, 0, 0,
	  .word = nft_word, .required = true },
	{ NFTA_SET_ELEM_LIST_ELEMENTS, NLA_KIND_NESTED_ARRAY, 0, 0,
	  nft_set_elem_key_attrs, ARRAY_SIZE(nft_set_elem_key_attrs),
	  .required = true },
};

static const struct nla_attr_spec nft_delsetelem_attrs[] = {
	{ NFTA_SET_ELEM_LIST_TABLE,    NLA_KIND_STRING_WORD, 0, 0,
	  .word = nft_word, .required = true },
	{ NFTA_SET_ELEM_LIST_SET,      NLA_KIND_STRING_WORD, 0, 0,
	  .word = nft_word, .required = true },
	{ NFTA_SET_ELEM_LIST_ELEMENTS, NLA_KIND_NESTED_ARRAY, 0, 0,
	  nft_set_elem_key_attrs, ARRAY_SIZE(nft_set_elem_key_attrs) },
};

/*
 * The object commands.  NEWOBJ answers -EINVAL unless the request holds the
 * type, the name and DATA, and fails a missing table the same way, so all four
 * are marked.  GETOBJ and GETOBJ_RESET need the table, the name and the type,
 * as do DELOBJ and DESTROYOBJ, which may name the object by a handle instead
 * of its name, drawn small as the others are.  The type is read
 * with ntohl(), and a number that no object type has makes nft_obj_type_get()
 * ask nft_request_module() for "nft-obj-<type>", which the batch loads with
 * request_module() before it runs again.  NFTA_OBJ_TYPE is therefore drawn
 * from the counter, 1, to NFT_OBJECT_MAX.  DATA is a bare nest that the
 * handler parses against the policy of the object's type, and nothing in a
 * request ties it to the type drawn; its children come from this table, the
 * first two of them as the 64-bit words most of those policies start with.
 * The use count is for replies.
 */
static const struct nla_attr_spec nft_newobj_attrs[] = {
	{ NFTA_OBJ_TABLE,    NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_OBJ_NAME,     NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_OBJ_TYPE,     NLA_KIND_BE32_RANGE, NFT_OBJECT_MAX,
	  NFT_OBJECT_COUNTER, .required = true },
	{ NFTA_OBJ_DATA,     NLA_KIND_NESTED, 0, .required = true },
	{ NFTA_OBJ_USERDATA, NLA_KIND_BINARY, 64 },
};

static const struct nla_attr_spec nft_obj_name_attrs[] = {
	{ NFTA_OBJ_TABLE,    NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_OBJ_NAME,     NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_OBJ_TYPE,     NLA_KIND_BE32_RANGE, NFT_OBJECT_MAX,
	  NFT_OBJECT_COUNTER, .required = true },
	{ NFTA_OBJ_HANDLE,   NLA_KIND_BE64_RANGE, 64, 1 },
};

/*
 * The flowtable commands.  NEWFLOWTABLE answers -EINVAL unless the request
 * holds the table, the name and HOOK, so all three are marked.  HOOK is
 * nft_flowtable_hook_policy's number, priority and devices:
 * nft_flowtable_parse_hook() answers -ENOENT unless it has the first two, and
 * -EOPNOTSUPP to a number other than NF_NETDEV_INGRESS.  DEVS names the
 * devices the flowtable hooks, looked up by nft_tables_parse_netdev_hooks()
 * as the chain hook's are.  GETFLOWTABLE needs the name and
 * the table, and DELFLOWTABLE and DESTROYFLOWTABLE the table and a name or a
 * handle, drawn small as the others are; a HOOK in a delete takes devices
 * out of the flowtable instead of deleting it, so it is left out as well.
 */
static const unsigned int nft_flowtable_hooknums[] = { NF_NETDEV_INGRESS };

static const struct nla_attr_spec nft_flowtable_hook_attrs[] = {
	{ NFTA_FLOWTABLE_HOOK_NUM,      NLA_KIND_BE32_ONEOF, 0, 0,
	  .oneof = nft_flowtable_hooknums,
	  .n_oneof = ARRAY_SIZE(nft_flowtable_hooknums), .required = true },
	{ NFTA_FLOWTABLE_HOOK_PRIORITY, NLA_KIND_U32, 4, .required = true },
	{ NFTA_FLOWTABLE_HOOK_DEVS,     NLA_KIND_NESTED, 0, 0,
	  nft_device_attrs, ARRAY_SIZE(nft_device_attrs) },
};

static const struct nla_attr_spec nft_newflowtable_attrs[] = {
	{ NFTA_FLOWTABLE_TABLE, NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_FLOWTABLE_NAME,  NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_FLOWTABLE_HOOK,  NLA_KIND_NESTED, 0, 0,
	  nft_flowtable_hook_attrs, ARRAY_SIZE(nft_flowtable_hook_attrs),
	  .required = true },
	{ NFTA_FLOWTABLE_FLAGS, NLA_KIND_BE32_MASK, NFT_FLOWTABLE_MASK },
};

static const struct nla_attr_spec nft_flowtable_name_attrs[] = {
	{ NFTA_FLOWTABLE_TABLE, NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_FLOWTABLE_NAME,  NLA_KIND_STRING_WORD, 0, 0, .word = nft_word,
	  .required = true },
	{ NFTA_FLOWTABLE_HANDLE, NLA_KIND_BE64_RANGE, 64, 1 },
};

/*
 * The NEW, DEL and DESTROY commands, 21 of the 32, are NFNL_CB_BATCH in
 * nf_tables_cb[] and marked as such; the GETs are NFNL_CB_RCU.
 */
static const struct nfnl_cmd_grammar nftables_cmds[] = {
	{ NFT_MSG_NEWTABLE,          "NFT_MSG_NEWTABLE", true,
	  nft_newtable_attrs, ARRAY_SIZE(nft_newtable_attrs) },
	{ NFT_MSG_GETTABLE,          "NFT_MSG_GETTABLE", false,
	  nft_gettable_attrs, ARRAY_SIZE(nft_gettable_attrs) },
	{ NFT_MSG_DELTABLE,          "NFT_MSG_DELTABLE", true,
	  nft_deltable_attrs, ARRAY_SIZE(nft_deltable_attrs) },
	{ NFT_MSG_DESTROYTABLE,      "NFT_MSG_DESTROYTABLE", true,
	  nft_deltable_attrs, ARRAY_SIZE(nft_deltable_attrs) },
	{ NFT_MSG_NEWCHAIN,          "NFT_MSG_NEWCHAIN", true,
	  nft_newchain_attrs, ARRAY_SIZE(nft_newchain_attrs) },
	{ NFT_MSG_GETCHAIN,          "NFT_MSG_GETCHAIN", false,
	  nft_chain_name_attrs, ARRAY_SIZE(nft_chain_name_attrs) },
	{ NFT_MSG_DELCHAIN,          "NFT_MSG_DELCHAIN", true,
	  nft_chain_name_attrs, ARRAY_SIZE(nft_chain_name_attrs) },
	{ NFT_MSG_DESTROYCHAIN,      "NFT_MSG_DESTROYCHAIN", true,
	  nft_chain_name_attrs, ARRAY_SIZE(nft_chain_name_attrs) },
	{ NFT_MSG_NEWRULE,           "NFT_MSG_NEWRULE", true,
	  nft_newrule_attrs, ARRAY_SIZE(nft_newrule_attrs) },
	{ NFT_MSG_GETRULE,           "NFT_MSG_GETRULE", false,
	  nft_getrule_attrs, ARRAY_SIZE(nft_getrule_attrs) },
	{ NFT_MSG_GETRULE_RESET,     "NFT_MSG_GETRULE_RESET", false,
	  nft_getrule_attrs, ARRAY_SIZE(nft_getrule_attrs) },
	{ NFT_MSG_DELRULE,           "NFT_MSG_DELRULE", true,
	  nft_delrule_attrs, ARRAY_SIZE(nft_delrule_attrs) },
	{ NFT_MSG_DESTROYRULE,       "NFT_MSG_DESTROYRULE", true,
	  nft_delrule_attrs, ARRAY_SIZE(nft_delrule_attrs) },
	{ NFT_MSG_NEWSET,            "NFT_MSG_NEWSET", true,
	  nft_newset_attrs, ARRAY_SIZE(nft_newset_attrs) },
	{ NFT_MSG_GETSET,            "NFT_MSG_GETSET", false,
	  nft_set_name_attrs, ARRAY_SIZE(nft_set_name_attrs) },
	{ NFT_MSG_DELSET,            "NFT_MSG_DELSET", true,
	  nft_set_name_attrs, ARRAY_SIZE(nft_set_name_attrs) },
	{ NFT_MSG_DESTROYSET,        "NFT_MSG_DESTROYSET", true,
	  nft_set_name_attrs, ARRAY_SIZE(nft_set_name_attrs) },
	{ NFT_MSG_NEWSETELEM,        "NFT_MSG_NEWSETELEM", true,
	  nft_newsetelem_attrs, ARRAY_SIZE(nft_newsetelem_attrs) },
	{ NFT_MSG_GETSETELEM,        "NFT_MSG_GETSETELEM", false,
	  nft_getsetelem_attrs, ARRAY_SIZE(nft_getsetelem_attrs) },
	{ NFT_MSG_GETSETELEM_RESET,  "NFT_MSG_GETSETELEM_RESET", false,
	  nft_getsetelem_attrs, ARRAY_SIZE(nft_getsetelem_attrs) },
	{ NFT_MSG_DELSETELEM,        "NFT_MSG_DELSETELEM", true,
	  nft_delsetelem_attrs, ARRAY_SIZE(nft_delsetelem_attrs) },
	{ NFT_MSG_DESTROYSETELEM,    "NFT_MSG_DESTROYSETELEM", true,
	  nft_delsetelem_attrs, ARRAY_SIZE(nft_delsetelem_attrs) },
	{ NFT_MSG_NEWOBJ,            "NFT_MSG_NEWOBJ", true,
	  nft_newobj_attrs, ARRAY_SIZE(nft_newobj_attrs) },
	{ NFT_MSG_GETOBJ,            "NFT_MSG_GETOBJ", false,
	  nft_obj_name_attrs, ARRAY_SIZE(nft_obj_name_attrs) },
	{ NFT_MSG_GETOBJ_RESET,      "NFT_MSG_GETOBJ_RESET", false,
	  nft_obj_name_attrs, ARRAY_SIZE(nft_obj_name_attrs) },
	{ NFT_MSG_DELOBJ,            "NFT_MSG_DELOBJ", true,
	  nft_obj_name_attrs, ARRAY_SIZE(nft_obj_name_attrs) },
	{ NFT_MSG_DESTROYOBJ,        "NFT_MSG_DESTROYOBJ", true,
	  nft_obj_name_attrs, ARRAY_SIZE(nft_obj_name_attrs) },
	{ NFT_MSG_NEWFLOWTABLE,      "NFT_MSG_NEWFLOWTABLE", true,
	  nft_newflowtable_attrs, ARRAY_SIZE(nft_newflowtable_attrs) },
	{ NFT_MSG_GETFLOWTABLE,      "NFT_MSG_GETFLOWTABLE", false,
	  nft_flowtable_name_attrs, ARRAY_SIZE(nft_flowtable_name_attrs) },
	{ NFT_MSG_DELFLOWTABLE,      "NFT_MSG_DELFLOWTABLE", true,
	  nft_flowtable_name_attrs, ARRAY_SIZE(nft_flowtable_name_attrs) },
	{ NFT_MSG_DESTROYFLOWTABLE,  "NFT_MSG_DESTROYFLOWTABLE", true,
	  nft_flowtable_name_attrs, ARRAY_SIZE(nft_flowtable_name_attrs) },
	/* No policy: nf_tables_cb[] gives it attr_count 0, so it reads no
	 * attribute and has no table. */
	{ NFT_MSG_GETGEN,            "NFT_MSG_GETGEN" },
};

/*
 * nft_supported_family() takes these six, each when the kernel is built with
 * it, and a table is found by its family and name together, so a batch sends
 * all its commands in one of them.
 */
static const unsigned char nftables_families[] = {
	NFPROTO_INET, NFPROTO_IPV4, NFPROTO_ARP, NFPROTO_NETDEV,
	NFPROTO_BRIDGE, NFPROTO_IPV6,
};

struct nfnl_subsys_grammar sub_nftables = {
	.name = "nftables",
	.subsys_id = NFNL_SUBSYS_NFTABLES,
	.cmds = nftables_cmds,
	.n_cmds = ARRAY_SIZE(nftables_cmds),
	.families = nftables_families,
	.n_families = ARRAY_SIZE(nftables_families),
};
