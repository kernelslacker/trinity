/*
 * Self-check for the typed-hypothesis credit the consume stash feeds: a
 * pull the live inject arm produced is credited to the hypothesis it was
 * derived from, however many others its value fits, and a raw pull or a
 * slot that no longer holds that hypothesis credits none.
 */

#include <stdint.h>
#include <stdlib.h>

#include "child.h"
#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "debug.h"		/* BUG */
#include "kcov.h"

extern struct childdata *fake_this_child;	/* fake_shm.c */

#define CREDIT_NR	9U
#define CREDIT_IP	0x4242UL
#define CREDIT_VALUE	0x40UL

static const struct cmp_hyp_ref from_exact = { 0, CMP_HYP_EXACT };
/* Slot 1 holds the ENUM_FAMILY, slot 2 is past the published pool. */
static const struct cmp_hyp_ref stale_kind = { 1, CMP_HYP_EXACT };
static const struct cmp_hyp_ref unpublished = { 2, CMP_HYP_EXACT };

static struct cmp_hypothesis *add_hyp(enum cmp_hypothesis_kind kind,
				      uint64_t lo, uint64_t hi)
{
	struct cmp_hyp_pool *pool = &cmp_hints_shm->hyp_pools[CREDIT_NR][0];
	struct cmp_hypothesis *h = &pool->entries[pool->count++];

	h->kind = kind;
	h->cmp_ip = CREDIT_IP;
	h->width = 4;
	h->exemplar = lo;
	h->lo = lo;
	h->hi = hi;
	return h;
}

static void stash(unsigned long value, const struct cmp_hyp_ref *hyp)
{
	cmp_hints_stash_consumed(CREDIT_NR, false, CMP_HINT_POOL_PER_SYSCALL,
				 CMP_HINT_CALLSITE_ARG_OP, CREDIT_IP, value, 4,
				 CMP_HINT_EXACT, false, 0, hyp, false);
}

void cmp_hyp_credit_self_check(void);
void cmp_hyp_credit_self_check(void)
{
	struct childdata *child;
	struct cmp_hypothesis *exact, *family, *pending;

	kcov_shm = calloc(1, sizeof(*kcov_shm));
	cmp_hints_shm = calloc(1, sizeof(*cmp_hints_shm));
	child = calloc(1, sizeof(*child));
	if (kcov_shm == NULL || cmp_hints_shm == NULL || child == NULL)
		BUG("cmp hyp credit: calloc failed");
	fake_this_child = child;

	/* An ENUM_FAMILY at the same site spans the EXACT's N+1 probe. */
	exact = add_hyp(CMP_HYP_EXACT, CREDIT_VALUE, CREDIT_VALUE);
	family = add_hyp(CMP_HYP_ENUM_FAMILY, CREDIT_VALUE - 1,
			 CREDIT_VALUE + 1);
	/* An EXACT written but not yet counted, as an append leaves it. */
	pending = add_hyp(CMP_HYP_EXACT, CREDIT_VALUE, CREDIT_VALUE);
	cmp_hints_shm->hyp_pools[CREDIT_NR][0].count--;

	/* A raw pull that happens to carry the EXACT's value. */
	stash(CREDIT_VALUE, NULL);
	if (exact->consumed_count != 0)
		BUG("cmp hyp credit: a raw pull counted as a typed consume");

	stash(CREDIT_VALUE + 1, &from_exact);
	if (exact->consumed_count != 1 || family->consumed_count != 0)
		BUG("cmp hyp credit: a consume missed the hypothesis the pull came from");
	cmp_hyp_credit_outcome(&child->cmp_hints_consumed_stash[1],
			       CMP_HYP_OUTCOME_MISS);
	if (exact->misses != 1 || family->misses != 0)
		BUG("cmp hyp credit: an outcome missed the hypothesis the pull came from");

	stash(CREDIT_VALUE, &stale_kind);
	stash(CREDIT_VALUE, &unpublished);
	if (family->consumed_count != 0 || pending->consumed_count != 0)
		BUG("cmp hyp credit: a slot that no longer matches was credited");
	if (kcov_shm->cmp_hyp_results.cmp_hyp_credit_slot_mismatch != 2)
		BUG("cmp hyp credit: a dropped credit went uncounted");

	fake_this_child = NULL;
	free(child);
	free(cmp_hints_shm);
	free(kcov_shm);
	cmp_hints_shm = NULL;
	kcov_shm = NULL;
}
