/*
 * internal-builders.h
 *
 * Table / chain / set / rule builder prototypes plus the small helper
 * pool that supports them (family picker, table-name filler) and the
 * dormant/fwd/l4frag sub-mode sweep entry points.  Split out of
 * internal.h; contents are moved verbatim.  Depends on
 * internal-state.h for the struct nft_expr_plan definition and for
 * the base types (struct nfnl_ctx, struct nl_ctx, __u8/32/64, size_t,
 * bool).
 */

#ifndef CHILDOPS_NFTABLES_CHURN_INTERNAL_BUILDERS_H
#define CHILDOPS_NFTABLES_CHURN_INTERNAL_BUILDERS_H

#include "internal-state.h"

int nft_build_newtable(struct nfnl_ctx *ctx, __u8 family, const char *table_name);
int nft_build_deltable(struct nfnl_ctx *ctx, __u8 family, const char *table_name);
int nft_build_newset(struct nfnl_ctx *ctx, __u8 family,
		 const char *table_name, const char *set_name, __u32 set_id);
int nft_build_delset(struct nfnl_ctx *ctx, __u8 family,
		 const char *table_name, const char *set_name);
int nft_build_newchain(struct nfnl_ctx *ctx, __u8 family,
		       const char *table_name, const char *chain_name,
		       bool hook_present);
int nft_build_newrule(struct nfnl_ctx *ctx, __u8 family,
		      const char *table_name, const char *chain_name,
		      const char *target_chain, __u32 verdict_code,
		      __u64 position, const struct nft_expr_plan *plan,
		      const char *set_name, __u32 set_id);
int nft_build_delrule(struct nfnl_ctx *ctx, __u8 family,
		      const char *table_name, const char *chain_name);
__u8 nft_pick_family(void);
void nft_fill_table_name(char *out, size_t cap, const char *prefix);

void nft_dormant_abort_sweep(struct nfnl_ctx *ctx);

void nft_fwd_netdev_loop_sweep(struct nfnl_ctx *nfnl, struct nl_ctx *rtnl);
bool nft_fwd_netdev_loop_unsupported(void);

void nft_l4_aware_frag_sweep(struct nfnl_ctx *nfnl);

#endif /* CHILDOPS_NFTABLES_CHURN_INTERNAL_BUILDERS_H */
