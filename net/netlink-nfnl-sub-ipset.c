/*
 * NETLINK_NETFILTER subsystem grammar: ip_set (NFNL_SUBSYS_IPSET).
 *
 * ip_set is the in-kernel hashtable / bitmap / list set engine that
 * iptables and nftables match against; the net/netfilter/ipset
 * directory hosts 15 IPSET_CMD_* commands across creation / lookup
 * / element ops.
 * The kernel registers the subsystem via nfnetlink_register_subsys()
 * with subsys_id NFNL_SUBSYS_IPSET, so the message is routed by the
 * standard nfnetlink dispatcher — there's no genl family resolution
 * to do, the subsys_id is a compile-time constant.
 *
 * Without this grammar, Trinity's nfnetlink generator emitted a
 * random nfgenmsg body and never produced any IPSET_ATTR_* TLVs, so
 * the per-cmd validate gates inside ip_set_core.c short-circuited
 * on missing-attribute errors before reaching the parser.  The
 * starter cmd set covers the read-side commands (LIST / HEADER /
 * TYPE / GET_BYNAME / GET_BYINDEX) plus the write-side counterparts
 * (CREATE / DESTROY / FLUSH / RENAME / SWAP / ADD / DEL / TEST).
 * Write commands need CAP_NET_ADMIN and will EPERM in unprivileged
 * children, but the dispatcher still walks the per-attr policy gate
 * before the perm check — so the validate paths get exercised
 * either way.
 *
 * Attribute set: the command-level IPSET_ATTR_* namespace from
 * include/uapi/linux/netfilter/ipset/ip_set.h, sized per the
 * kernel's nla_policy entries in ip_set_core.c
 * (ip_set_create_policy / ip_set_setname_policy / ip_set_dump_policy
 * / ip_set_type_policy / ip_set_protocol_policy /
 * ip_set_index_policy).  Each emitted attribute is sized to what
 * those policies expect: PROTOCOL/REVISION/FAMILY are NLA_U8,
 * SETNAME/TYPENAME are NLA_NUL_STRING capped at IPSET_MAXNAMELEN-1
 * (=31), FLAGS is NLA_U32, INDEX is NLA_U16, DATA is NLA_NESTED.
 * The nested DATA payload (per-set-type CADT/ADT attrs) needs its
 * own nested grammar table and is left for follow-up — the
 * length-only NESTED header still exercises the nested parser's
 * bounds checks.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ipset/ip_set.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

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
 * Command-level IPSET_ATTR_* attribute spec table.
 *
 * The kernel's per-cmd nla_policy gates each draw a different subset
 * out of this namespace; emitting the union is harmless — attrs not
 * declared by a given cmd's policy either get NLA_POLICY_UNSPEC'd
 * (accepted, hand-validated) or rejected with -EINVAL, and either
 * branch exercises real parser code.
 *
 * IPSET_ATTR_SETNAME / IPSET_ATTR_TYPENAME are NLA_NUL_STRING with
 * a hard cap at IPSET_MAXNAMELEN-1 (=31) — anything longer trips the
 * NLA_NUL_STRING length validator before the dispatch helpers ever
 * see the payload.  IPSET_ATTR_DATA is the per-set-type CADT/ADT
 * envelope; emitted as a length-only NESTED header here, the inner
 * grammar belongs in a follow-up.
 */
static const struct nla_attr_spec ipset_attrs[] = {
	{ IPSET_ATTR_PROTOCOL, NLA_KIND_U8,     1 },
	{ IPSET_ATTR_SETNAME,  NLA_KIND_STRING, IPSET_MAXNAMELEN - 1 },
	{ IPSET_ATTR_TYPENAME, NLA_KIND_STRING, IPSET_MAXNAMELEN - 1 },
	{ IPSET_ATTR_REVISION, NLA_KIND_U8,     1 },
	{ IPSET_ATTR_FAMILY,   NLA_KIND_U8,     1 },
	{ IPSET_ATTR_FLAGS,    NLA_KIND_U32,    4 },
	{ IPSET_ATTR_DATA,     NLA_KIND_NESTED, 0 },
	{ IPSET_ATTR_LINENO,   NLA_KIND_U32,    4 },
	{ IPSET_ATTR_INDEX,    NLA_KIND_U16,    2 },
};

struct nfnl_subsys_grammar sub_ipset = {
	.name = "ipset",
	.subsys_id = NFNL_SUBSYS_IPSET,
	.cmds = ipset_cmds,
	.n_cmds = ARRAY_SIZE(ipset_cmds),
	.attrs = ipset_attrs,
	.n_attrs = ARRAY_SIZE(ipset_attrs),
};
