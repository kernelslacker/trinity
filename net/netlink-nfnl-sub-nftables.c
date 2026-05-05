/*
 * NETLINK_NETFILTER subsystem grammar: nftables (NFNL_SUBSYS_NFTABLES).
 *
 * The nftables control plane is an unusually broad surface inside
 * netfilter — net/netfilter/nf_tables_api.c hosts ~30 NFT_MSG_*
 * commands across the table / chain / rule / set / setelem / obj /
 * flowtable / gen namespaces, each with its own nla_policy gate.
 * The starter cmd set covers the read-side (GETTABLE / GETCHAIN /
 * GETRULE / GETSET / GETOBJ / GETFLOWTABLE / GETGEN) plus the write
 * counterparts for the four most-trafficked namespaces (TABLE /
 * CHAIN / RULE / SET).  Write commands need CAP_NET_ADMIN in the
 * net namespace and will EPERM in unprivileged children, but the
 * dispatcher still runs the per-attr validate gate before the perm
 * check — so the attr policy paths get exercised either way.
 *
 * The attr table mirrors the per-namespace NFTA_*_* enums for the
 * starter command set: TABLE_NAME / CHAIN_TABLE / RULE_CHAIN are the
 * common identifying string pairs the dispatcher uses to look up
 * the target object before dispatching deeper.  Each NESTED entry
 * (HOOK / EXPRESSIONS) is emitted as a length-only header — the
 * inner element grammar lives in the kernel's per-namespace policy
 * tables and would need its own nested-grammar registry to do well.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar nftables_cmds[] = {
	{ NFT_MSG_NEWTABLE,     "NFT_MSG_NEWTABLE" },
	{ NFT_MSG_GETTABLE,     "NFT_MSG_GETTABLE" },
	{ NFT_MSG_DELTABLE,     "NFT_MSG_DELTABLE" },
	{ NFT_MSG_NEWCHAIN,     "NFT_MSG_NEWCHAIN" },
	{ NFT_MSG_GETCHAIN,     "NFT_MSG_GETCHAIN" },
	{ NFT_MSG_DELCHAIN,     "NFT_MSG_DELCHAIN" },
	{ NFT_MSG_NEWRULE,      "NFT_MSG_NEWRULE" },
	{ NFT_MSG_GETRULE,      "NFT_MSG_GETRULE" },
	{ NFT_MSG_DELRULE,      "NFT_MSG_DELRULE" },
	{ NFT_MSG_NEWSET,       "NFT_MSG_NEWSET" },
	{ NFT_MSG_GETSET,       "NFT_MSG_GETSET" },
	{ NFT_MSG_DELSET,       "NFT_MSG_DELSET" },
	{ NFT_MSG_GETOBJ,       "NFT_MSG_GETOBJ" },
	{ NFT_MSG_GETFLOWTABLE, "NFT_MSG_GETFLOWTABLE" },
	{ NFT_MSG_GETGEN,       "NFT_MSG_GETGEN" },
};

/*
 * NFTA_* attr spec table — covers the table/chain/rule/set top-level
 * namespaces, which are what userspace tooling spends most of its
 * time emitting.  The four namespaces share the same attr-type
 * numbering (NFTA_TABLE_NAME=1, NFTA_CHAIN_TABLE=1, etc), but the
 * per-namespace nla_policy gates strip attrs not in their declared
 * set — the union here is just the permissive emit shape.
 */
static const struct nla_attr_spec nftables_attrs[] = {
	/* NFT_MSG_*TABLE */
	{ NFTA_TABLE_NAME,       NLA_KIND_STRING, 32 },
	{ NFTA_TABLE_FLAGS,      NLA_KIND_U32,    4 },
	{ NFTA_TABLE_HANDLE,     NLA_KIND_U64,    8 },
	{ NFTA_TABLE_USERDATA,   NLA_KIND_BINARY, 64 },
	/* NFT_MSG_*CHAIN */
	{ NFTA_CHAIN_TABLE,      NLA_KIND_STRING, 32 },
	{ NFTA_CHAIN_HANDLE,     NLA_KIND_U64,    8 },
	{ NFTA_CHAIN_NAME,       NLA_KIND_STRING, 32 },
	{ NFTA_CHAIN_HOOK,       NLA_KIND_NESTED, 0 },
	{ NFTA_CHAIN_POLICY,     NLA_KIND_U32,    4 },
	{ NFTA_CHAIN_TYPE,       NLA_KIND_STRING, 16 },
	{ NFTA_CHAIN_FLAGS,      NLA_KIND_U32,    4 },
	{ NFTA_CHAIN_USERDATA,   NLA_KIND_BINARY, 64 },
	/* NFT_MSG_*RULE */
	{ NFTA_RULE_TABLE,       NLA_KIND_STRING, 32 },
	{ NFTA_RULE_CHAIN,       NLA_KIND_STRING, 32 },
	{ NFTA_RULE_HANDLE,      NLA_KIND_U64,    8 },
	{ NFTA_RULE_EXPRESSIONS, NLA_KIND_NESTED, 0 },
	{ NFTA_RULE_POSITION,    NLA_KIND_U64,    8 },
	{ NFTA_RULE_USERDATA,    NLA_KIND_BINARY, 64 },
	/* NFT_MSG_*SET */
	{ NFTA_SET_TABLE,        NLA_KIND_STRING, 32 },
	{ NFTA_SET_NAME,         NLA_KIND_STRING, 32 },
	{ NFTA_SET_FLAGS,        NLA_KIND_U32,    4 },
	{ NFTA_SET_KEY_TYPE,     NLA_KIND_U32,    4 },
	{ NFTA_SET_KEY_LEN,      NLA_KIND_U32,    4 },
	{ NFTA_SET_DATA_TYPE,    NLA_KIND_U32,    4 },
	{ NFTA_SET_DATA_LEN,     NLA_KIND_U32,    4 },
	{ NFTA_SET_POLICY,       NLA_KIND_U32,    4 },
	{ NFTA_SET_TIMEOUT,      NLA_KIND_U64,    8 },
	{ NFTA_SET_USERDATA,     NLA_KIND_BINARY, 64 },
};

struct nfnl_subsys_grammar sub_nftables = {
	.name = "nftables",
	.subsys_id = NFNL_SUBSYS_NFTABLES,
	.cmds = nftables_cmds,
	.n_cmds = ARRAY_SIZE(nftables_cmds),
	.attrs = nftables_attrs,
	.n_attrs = ARRAY_SIZE(nftables_attrs),
};
