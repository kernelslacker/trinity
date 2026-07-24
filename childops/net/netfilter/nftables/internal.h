/*
 * internal.h
 *
 * Include aggregator for the nftables/ TU cluster.  The private API
 * previously carried in this file has been split by owner into the
 * five internal-*.h shards below; consumers still #include "internal.h"
 * and see the union of those declarations unchanged.
 *
 * This header is private to the nftables/ TUs — do not include it
 * from anywhere else.
 */

#ifndef CHILDOPS_NFTABLES_CHURN_INTERNAL_H
#define CHILDOPS_NFTABLES_CHURN_INTERNAL_H

#include "internal-state.h"
#include "internal-compat.h"
#include "internal-builders.h"
#include "internal-exprs.h"
#include "internal-stats.h"

#endif /* CHILDOPS_NFTABLES_CHURN_INTERNAL_H */
