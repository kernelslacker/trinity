/*
 * NETLINK_NETFILTER subsystem grammar: nftables (NFNL_SUBSYS_NFTABLES).
 *
 * The nftables control plane is an unusually broad surface inside
 * netfilter — net/netfilter/nf_tables_api.c hosts the full NFT_MSG_*
 * matrix across the table / chain / rule / set / setelem / obj /
 * flowtable / gen namespaces, each with its own nla_policy gate.
 * The cmd set below covers every current nf_tables_msg_types entry:
 * the read / write / destroy triples per namespace, the *_RESET
 * dump variants, and the gen readback.  Write and destroy commands
 * need CAP_NET_ADMIN in the net namespace and will EPERM in
 * unprivileged children, but the dispatcher still runs the per-attr
 * validate gate before the perm check — so the attr policy paths
 * get exercised either way.
 *
 * The attr table mirrors the per-namespace NFTA_*_* enums for the
 * table / chain / rule / set / setelem / obj / flowtable namespaces.
 * The namespaces share attr-type numbering (NFTA_TABLE_NAME=1,
 * NFTA_CHAIN_TABLE=1, etc), but the per-namespace nla_policy gates
 * strip attrs not in their declared set — the union here is just
 * the permissive emit shape.  Each NESTED entry (HOOK / EXPRESSIONS
 * / KEY / DATA / ...) is emitted as a length-only header — the
 * inner element grammar lives in the kernel's per-namespace policy
 * tables and would need its own nested-grammar registry to do well.
 */

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
#ifndef NFTA_OBJ_USE
#define NFTA_OBJ_USE			5
#endif
#ifndef NFTA_OBJ_HANDLE
#define NFTA_OBJ_HANDLE			6
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
#ifndef NFTA_FLOWTABLE_USE
#define NFTA_FLOWTABLE_USE		4
#endif
#ifndef NFTA_FLOWTABLE_HANDLE
#define NFTA_FLOWTABLE_HANDLE		5
#endif
#ifndef NFTA_FLOWTABLE_FLAGS
#define NFTA_FLOWTABLE_FLAGS		7
#endif

static const struct nfnl_cmd_grammar nftables_cmds[] = {
	{ NFT_MSG_NEWTABLE,          "NFT_MSG_NEWTABLE" },
	{ NFT_MSG_GETTABLE,          "NFT_MSG_GETTABLE" },
	{ NFT_MSG_DELTABLE,          "NFT_MSG_DELTABLE" },
	{ NFT_MSG_DESTROYTABLE,      "NFT_MSG_DESTROYTABLE" },
	{ NFT_MSG_NEWCHAIN,          "NFT_MSG_NEWCHAIN" },
	{ NFT_MSG_GETCHAIN,          "NFT_MSG_GETCHAIN" },
	{ NFT_MSG_DELCHAIN,          "NFT_MSG_DELCHAIN" },
	{ NFT_MSG_DESTROYCHAIN,      "NFT_MSG_DESTROYCHAIN" },
	{ NFT_MSG_NEWRULE,           "NFT_MSG_NEWRULE" },
	{ NFT_MSG_GETRULE,           "NFT_MSG_GETRULE" },
	{ NFT_MSG_GETRULE_RESET,     "NFT_MSG_GETRULE_RESET" },
	{ NFT_MSG_DELRULE,           "NFT_MSG_DELRULE" },
	{ NFT_MSG_DESTROYRULE,       "NFT_MSG_DESTROYRULE" },
	{ NFT_MSG_NEWSET,            "NFT_MSG_NEWSET" },
	{ NFT_MSG_GETSET,            "NFT_MSG_GETSET" },
	{ NFT_MSG_DELSET,            "NFT_MSG_DELSET" },
	{ NFT_MSG_DESTROYSET,        "NFT_MSG_DESTROYSET" },
	{ NFT_MSG_NEWSETELEM,        "NFT_MSG_NEWSETELEM" },
	{ NFT_MSG_GETSETELEM,        "NFT_MSG_GETSETELEM" },
	{ NFT_MSG_GETSETELEM_RESET,  "NFT_MSG_GETSETELEM_RESET" },
	{ NFT_MSG_DELSETELEM,        "NFT_MSG_DELSETELEM" },
	{ NFT_MSG_DESTROYSETELEM,    "NFT_MSG_DESTROYSETELEM" },
	{ NFT_MSG_NEWOBJ,            "NFT_MSG_NEWOBJ" },
	{ NFT_MSG_GETOBJ,            "NFT_MSG_GETOBJ" },
	{ NFT_MSG_GETOBJ_RESET,      "NFT_MSG_GETOBJ_RESET" },
	{ NFT_MSG_DELOBJ,            "NFT_MSG_DELOBJ" },
	{ NFT_MSG_DESTROYOBJ,        "NFT_MSG_DESTROYOBJ" },
	{ NFT_MSG_NEWFLOWTABLE,      "NFT_MSG_NEWFLOWTABLE" },
	{ NFT_MSG_GETFLOWTABLE,      "NFT_MSG_GETFLOWTABLE" },
	{ NFT_MSG_DELFLOWTABLE,      "NFT_MSG_DELFLOWTABLE" },
	{ NFT_MSG_DESTROYFLOWTABLE,  "NFT_MSG_DESTROYFLOWTABLE" },
	{ NFT_MSG_GETGEN,            "NFT_MSG_GETGEN" },
};

/*
 * NFTA_* attr spec table — covers the table / chain / rule / set /
 * setelem / obj / flowtable top-level namespaces, which are what
 * userspace tooling spends most of its time emitting.  The
 * namespaces share the same attr-type numbering (NFTA_TABLE_NAME=1,
 * NFTA_CHAIN_TABLE=1, etc), but the per-namespace nla_policy gates
 * strip attrs not in their declared set — the union here is just
 * the permissive emit shape.
 */
static const struct nla_attr_spec nftables_attrs[] = {
	/* NFT_MSG_*TABLE */
	{ NFTA_TABLE_NAME,           NLA_KIND_STRING, 32 },
	{ NFTA_TABLE_FLAGS,          NLA_KIND_U32,    4 },
	{ NFTA_TABLE_HANDLE,         NLA_KIND_U64,    8 },
	{ NFTA_TABLE_USERDATA,       NLA_KIND_BINARY, 64 },
	/* NFT_MSG_*CHAIN */
	{ NFTA_CHAIN_TABLE,          NLA_KIND_STRING, 32 },
	{ NFTA_CHAIN_HANDLE,         NLA_KIND_U64,    8 },
	{ NFTA_CHAIN_NAME,           NLA_KIND_STRING, 32 },
	{ NFTA_CHAIN_HOOK,           NLA_KIND_NESTED, 0 },
	{ NFTA_CHAIN_POLICY,         NLA_KIND_U32,    4 },
	{ NFTA_CHAIN_TYPE,           NLA_KIND_STRING, 16 },
	{ NFTA_CHAIN_FLAGS,          NLA_KIND_U32,    4 },
	{ NFTA_CHAIN_USERDATA,       NLA_KIND_BINARY, 64 },
	/* NFT_MSG_*RULE */
	{ NFTA_RULE_TABLE,           NLA_KIND_STRING, 32 },
	{ NFTA_RULE_CHAIN,           NLA_KIND_STRING, 32 },
	{ NFTA_RULE_HANDLE,          NLA_KIND_U64,    8 },
	{ NFTA_RULE_EXPRESSIONS,     NLA_KIND_NESTED, 0 },
	{ NFTA_RULE_POSITION,        NLA_KIND_U64,    8 },
	{ NFTA_RULE_USERDATA,        NLA_KIND_BINARY, 64 },
	/* NFT_MSG_*SET */
	{ NFTA_SET_TABLE,            NLA_KIND_STRING, 32 },
	{ NFTA_SET_NAME,             NLA_KIND_STRING, 32 },
	{ NFTA_SET_FLAGS,            NLA_KIND_U32,    4 },
	{ NFTA_SET_KEY_TYPE,         NLA_KIND_U32,    4 },
	{ NFTA_SET_KEY_LEN,          NLA_KIND_U32,    4 },
	{ NFTA_SET_DATA_TYPE,        NLA_KIND_U32,    4 },
	{ NFTA_SET_DATA_LEN,         NLA_KIND_U32,    4 },
	{ NFTA_SET_POLICY,           NLA_KIND_U32,    4 },
	{ NFTA_SET_TIMEOUT,          NLA_KIND_U64,    8 },
	{ NFTA_SET_USERDATA,         NLA_KIND_BINARY, 64 },
	/* NFT_MSG_*SETELEM */
	{ NFTA_SET_ELEM_KEY,         NLA_KIND_NESTED, 0 },
	{ NFTA_SET_ELEM_DATA,        NLA_KIND_NESTED, 0 },
	{ NFTA_SET_ELEM_FLAGS,       NLA_KIND_U32,    4 },
	{ NFTA_SET_ELEM_TIMEOUT,     NLA_KIND_U64,    8 },
	{ NFTA_SET_ELEM_EXPIRATION,  NLA_KIND_U64,    8 },
	{ NFTA_SET_ELEM_USERDATA,    NLA_KIND_BINARY, 64 },
	{ NFTA_SET_ELEM_EXPR,        NLA_KIND_NESTED, 0 },
	{ NFTA_SET_ELEM_OBJREF,      NLA_KIND_STRING, 32 },
	{ NFTA_SET_ELEM_KEY_END,     NLA_KIND_NESTED, 0 },
	{ NFTA_SET_ELEM_EXPRESSIONS, NLA_KIND_NESTED, 0 },
	/* NFT_MSG_*OBJ */
	{ NFTA_OBJ_TABLE,            NLA_KIND_STRING, 32 },
	{ NFTA_OBJ_NAME,             NLA_KIND_STRING, 32 },
	{ NFTA_OBJ_TYPE,             NLA_KIND_U32,    4 },
	{ NFTA_OBJ_DATA,             NLA_KIND_NESTED, 0 },
	{ NFTA_OBJ_USE,              NLA_KIND_U32,    4 },
	{ NFTA_OBJ_HANDLE,           NLA_KIND_U64,    8 },
	{ NFTA_OBJ_USERDATA,         NLA_KIND_BINARY, 64 },
	/* NFT_MSG_*FLOWTABLE */
	{ NFTA_FLOWTABLE_TABLE,      NLA_KIND_STRING, 32 },
	{ NFTA_FLOWTABLE_NAME,       NLA_KIND_STRING, 32 },
	{ NFTA_FLOWTABLE_HOOK,       NLA_KIND_NESTED, 0 },
	{ NFTA_FLOWTABLE_USE,        NLA_KIND_U32,    4 },
	{ NFTA_FLOWTABLE_HANDLE,     NLA_KIND_U64,    8 },
	{ NFTA_FLOWTABLE_FLAGS,      NLA_KIND_U32,    4 },
};

struct nfnl_subsys_grammar sub_nftables = {
	.name = "nftables",
	.subsys_id = NFNL_SUBSYS_NFTABLES,
	.cmds = nftables_cmds,
	.n_cmds = ARRAY_SIZE(nftables_cmds),
	.attrs = nftables_attrs,
	.n_attrs = ARRAY_SIZE(nftables_attrs),
};
