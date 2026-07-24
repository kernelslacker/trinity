/*
 * internal.h
 *
 * Shared declarations split out of childops/net/netfilter/nftables/churn.c to allow
 * the nftables_churn helper families to live in their own translation
 * units and compile in parallel with the dispatched entry point.  This
 * header is private to the nftables/ TUs — do not include it from
 * anywhere else.
 *
 * Contents:
 *   - the UAPI conditional #includes and their fallback macros, so the
 *     cluster sees exactly the same nf_tables symbol values;
 *   - static-inline nla_put_be{32,16,64} netlink helpers, kept inline
 *     so the linker does not see them as external (no real linkage
 *     change);
 *   - forward declarations for helpers deliberately widened from
 *     file-static to external linkage so the orchestration and sub-mode
 *     TUs can share builders without changing behaviour.
 */

#ifndef CHILDOPS_NFTABLES_CHURN_INTERNAL_H
#define CHILDOPS_NFTABLES_CHURN_INTERNAL_H

#include "internal-state.h"

#include "internal-compat.h"
#include "internal-builders.h"
#include "internal-exprs.h"

void nft_expr_plan_randomize(struct nft_expr_plan *plan);
void nft_expr_plan_record_stats(const struct nft_expr_plan *plan);

#endif /* CHILDOPS_NFTABLES_CHURN_INTERNAL_H */
