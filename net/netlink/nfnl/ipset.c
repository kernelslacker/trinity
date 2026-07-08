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
 *
 * The nested IPSET_ATTR_DATA payload carries the per-set-type CADT
 * (create/add/delete/test) attrs and the create-only sizing attrs —
 * IP / CIDR / PORT / TIMEOUT / PROTO / CADT_FLAGS on the CADT side,
 * HASHSIZE / MAXELEM / NETMASK / MARKMASK / BUCKETSIZE / RESIZE /
 * SIZE / INITVAL on the create-only side.  The kernel-side sub
 * policies live in each set-type module (ip_set_hash_ip.c,
 * ip_set_hash_net.c, ip_set_bitmap_ip.c, ...) and share the CADT id
 * namespace defined in <linux/netfilter/ipset/ip_set.h>.
 *
 * That inner namespace has id collisions with the outer one — e.g.
 * IPSET_ATTR_IP (=1) collides with IPSET_ATTR_PROTOCOL (=1),
 * IPSET_ATTR_PROTO (=7) collides with IPSET_ATTR_DATA (=7) — because
 * the kernel matches every child against the policy of whichever
 * nest is currently being parsed, so per-namespace id reuse is fine.
 * The spec-driven emitter picks entries by index rather than by id,
 * which lets the outer and inner definitions coexist in one flat
 * table (mirrors the pattern established for macsec in
 * net/netlink/genl/macsec.c, which stacks its outer and per-nest
 * definitions into a single spec array for the same reason).  When
 * the emitter picks IPSET_ATTR_DATA it recurses back into this same
 * table for children, so a fraction of DATA payloads land on the
 * CADT/create entries and the rest are outer attrs the per-set-type
 * policy will -EINVAL — both branches walk real parser code.
 */

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
 * Command-level IPSET_ATTR_* + nested IPSET_ATTR_DATA grammar.
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
 * see the payload.
 *
 * Below the outer block are the CADT / create-only attrs the per-
 * set-type modules validate under IPSET_ATTR_DATA.  Sizes match the
 * NLA_U8 / NLA_U16 / NLA_U32 / NLA_NESTED entries in the per-type
 * policies (see ip_set_hash_ip.c, ip_set_hash_net.c,
 * ip_set_bitmap_ip.c, ...) — IP / IP_TO / BITMASK are NLA_NESTED
 * (inner IPSET_ATTR_IPADDR_IPV4 / IPADDR_IPV6 addr block); PORT /
 * PORT_TO are NLA_U16 (kernel reads big-endian via ntohs, but the
 * on-wire width is what the validator gates on); TIMEOUT /
 * CADT_FLAGS / MARK / MARKMASK / INITVAL / HASHSIZE / MAXELEM /
 * SIZE are NLA_U32; CIDR / PROTO / NETMASK / BUCKETSIZE / RESIZE
 * are NLA_U8.
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
};

struct nfnl_subsys_grammar sub_ipset = {
	.name = "ipset",
	.subsys_id = NFNL_SUBSYS_IPSET,
	.cmds = ipset_cmds,
	.n_cmds = ARRAY_SIZE(ipset_cmds),
	.attrs = ipset_attrs,
	.n_attrs = ARRAY_SIZE(ipset_attrs),
};
