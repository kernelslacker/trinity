/*
 * internal-stats.h
 *
 * Stats/latch helpers for the nft_expr_plan lifecycle.  Split out of
 * internal.h; contents are moved verbatim.  Depends on
 * internal-state.h for struct nft_expr_plan.
 */

#ifndef CHILDOPS_NFTABLES_CHURN_INTERNAL_STATS_H
#define CHILDOPS_NFTABLES_CHURN_INTERNAL_STATS_H

#include "internal-state.h"

void nft_expr_plan_randomize(struct nft_expr_plan *plan);
void nft_expr_plan_record_stats(const struct nft_expr_plan *plan);

#endif /* CHILDOPS_NFTABLES_CHURN_INTERNAL_STATS_H */
