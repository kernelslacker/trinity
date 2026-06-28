/*
 * NETLINK_NETFILTER subsystem grammar: nft_compat (NFNL_SUBSYS_NFT_COMPAT).
 *
 * nft_compat is the xtables-over-nft shim: it marshals iptables-style
 * match/target lookups across nfnetlink so nft can resolve revisions
 * and info-blob shapes against the in-kernel xt_match/xt_target
 * registries.  Lives in net/netfilter/nft_compat.c, gated by
 * CONFIG_NFT_COMPAT.  The subsys is registered with
 * nfnetlink_subsystem_register() under subsys_id NFNL_SUBSYS_NFT_COMPAT
 * (11), so messages route through the standard nfnetlink dispatcher
 * — no genl family resolution to do.
 *
 * Without this grammar, Trinity's nfnetlink generator emitted a random
 * nfgenmsg body and never produced any NFTA_COMPAT_* TLVs, so the
 * per-cmd validate gate inside nft_compat.c short-circuited on
 * missing-attribute errors (NAME / REV / TYPE are all required by the
 * GET handler) before the xt_match/xt_target lookup paths ever ran.
 *
 * Command set: a single user-facing command (GET) per the
 * nfnl_nft_compat_cb[] callback table; the kernel exposes no NEW/DEL
 * — this subsys is read-only metadata.  GET does not require
 * CAP_NET_ADMIN, so the policy-validate path and the underlying
 * xt_request_find_match/xt_request_find_target lookups are exercised
 * in unprivileged children too.
 *
 * Attribute set: NFTA_COMPAT_* from nf_tables_compat.h, sized per
 * nfnl_compat_policy in net/netfilter/nft_compat.c.  NFTA_COMPAT_NAME
 * is NLA_NUL_STRING capped at NFT_COMPAT_NAME_MAX-1 (=31); NFTA_COMPAT_REV
 * and NFTA_COMPAT_TYPE are NLA_U32.  All three are required by the
 * handler — the policy validate gate rejects the message before the
 * lookup if any is absent, so emitting all three reliably reaches the
 * xt_request_find_*() resolvers (where the interesting state lives).
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables_compat.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar nft_compat_cmds[] = {
	{ NFNL_MSG_COMPAT_GET, "NFNL_MSG_COMPAT_GET" },
};

static const struct nla_attr_spec nft_compat_attrs[] = {
	{ NFTA_COMPAT_NAME, NLA_KIND_STRING, NFT_COMPAT_NAME_MAX - 1 },
	{ NFTA_COMPAT_REV,  NLA_KIND_U32,    4 },
	{ NFTA_COMPAT_TYPE, NLA_KIND_U32,    4 },
};

struct nfnl_subsys_grammar sub_nft_compat = {
	.name = "nft_compat",
	.subsys_id = NFNL_SUBSYS_NFT_COMPAT,
	.cmds = nft_compat_cmds,
	.n_cmds = ARRAY_SIZE(nft_compat_cmds),
	.attrs = nft_compat_attrs,
	.n_attrs = ARRAY_SIZE(nft_compat_attrs),
};
