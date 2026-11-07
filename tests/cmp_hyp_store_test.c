/*
 * Self-check for the typed-hypothesis store cmp_hyp_observe() fills: a
 * comparison site keeps one RANGE hypothesis, whose bounds follow the
 * site's cluster as it widens, and a second site that sees the same
 * values keeps its own, since the picker serves a hypothesis only at its
 * own site.  A kind at its cap gives a new hypothesis the slot of a
 * RETIRED one, or else of one at a site the durable pool no longer
 * holds, a PROMOTED one last, and never one the live arm can still reach.
 * A pool whose every kind is at its cap is full.
 */

#include <stdint.h>
#include <stdlib.h>

#include "cmp_hints.h"
#include "debug.h"		/* BUG */
#include "kcov.h"

#define STORE_NR	11U
#define REUSE_NR	12U
#define FULL_NR		13U
#define SITE_A		0x5150UL
#define SITE_B		0x5151UL

static unsigned int hyps_at(const struct cmp_hyp_pool *pool,
			    enum cmp_hypothesis_kind kind,
			    unsigned long cmp_ip,
			    const struct cmp_hypothesis **last)
{
	unsigned int i, n = 0;

	for (i = 0; i < pool->count; i++) {
		const struct cmp_hypothesis *h = &pool->entries[i];

		if (h->kind == kind && h->cmp_ip == cmp_ip) {
			*last = h;
			n++;
		}
	}
	return n;
}

static void check_range_per_site(void)
{
	struct cmp_hyp_pool *pool = &cmp_hints_shm->hyp_pools[STORE_NR][0];
	const struct cmp_hypothesis *r = NULL;
	unsigned long v;

	/* The third value makes a RANGE, and each one after widens it. */
	for (v = 10; v <= 14; v++) {
		cmp_hyp_observe(STORE_NR, false, SITE_A, v, 4);
		cmp_hyp_observe(STORE_NR, false, SITE_B, v, 4);
	}
	if (hyps_at(pool, CMP_HYP_RANGE, SITE_A, &r) != 1 ||
	    r->lo != 10 || r->hi != 14)
		BUG("cmp hyp store: a widening site kept a RANGE per step, or stale bounds");
	if (hyps_at(pool, CMP_HYP_RANGE, SITE_B, &r) != 1 ||
	    r->lo != 10 || r->hi != 14)
		BUG("cmp hyp store: a second site with the same range got none of its own");
}

/* Leave NR's durable pool holding one entry, at CMP_IP. */
static void hold_site(unsigned int nr, unsigned long cmp_ip)
{
	struct cmp_hint_pool *raw = &cmp_hints_shm->pools[nr][0];

	raw->entries[0].cmp_ip = cmp_ip;
	raw->entries[0].size = 4;
	raw->count = 1;
}

static void check_slot_reuse(void)
{
	struct cmp_hyp_pool *pool = &cmp_hints_shm->hyp_pools[REUSE_NR][0];
	struct cmp_hypothesis *retired = NULL, *promoted = NULL;
	const struct cmp_hypothesis *h = NULL;
	unsigned int i;

	/* Values too far apart for a RANGE, none of them a single bit. */
	hold_site(REUSE_NR, SITE_A);
	for (i = 0; i < CMP_HYP_PER_KIND; i++)
		cmp_hyp_observe(REUSE_NR, false, SITE_A, 0x1003 + i * 0x100, 4);
	cmp_hyp_observe(REUSE_NR, false, SITE_B, 0x7003, 4);
	if (hyps_at(pool, CMP_HYP_EXACT, SITE_B, &h) != 0)
		BUG("cmp hyp store: a full kind gave away a slot the live arm can still reach");

	for (i = 0; i < pool->count; i++) {
		struct cmp_hypothesis *e = &pool->entries[i];

		if (e->kind != CMP_HYP_EXACT)
			continue;
		if (retired == NULL)
			retired = e;
		else if (promoted == NULL)
			promoted = e;
	}
	retired->state = CMP_HYP_STATE_RETIRED;
	promoted->state = CMP_HYP_STATE_PROMOTED;

	cmp_hyp_observe(REUSE_NR, false, SITE_B, 0x7103, 4);
	if (hyps_at(pool, CMP_HYP_EXACT, SITE_B, &h) != 1 || h != retired)
		BUG("cmp hyp store: a full kind kept a RETIRED hypothesis's slot from a new one");

	/* SITE_A leaves the durable pool, and its hypotheses the live
	 * arm's reach. */
	hold_site(REUSE_NR, SITE_B);
	cmp_hyp_observe(REUSE_NR, false, SITE_B, 0x7203, 4);
	if (hyps_at(pool, CMP_HYP_EXACT, SITE_B, &h) != 2)
		BUG("cmp hyp store: a full kind kept slots the live arm can no longer reach");
	if (promoted->cmp_ip != SITE_A ||
	    promoted->state != CMP_HYP_STATE_PROMOTED)
		BUG("cmp hyp store: a PROMOTED hypothesis gave up its slot before an unproven one");
	if (pool->per_kind_count[CMP_HYP_EXACT] != CMP_HYP_PER_KIND)
		BUG("cmp hyp store: a reused slot was counted as a new one");
	if (kcov_shm->hyp_flat.cmp_hyp_kind_full != 1)
		BUG("cmp hyp store: a refused insert went uncounted, or a reuse counted as one");
}

static void check_full_pool(void)
{
	struct cmp_hyp_pool *pool = &cmp_hints_shm->hyp_pools[FULL_NR][0];
	unsigned long kind_full = kcov_shm->hyp_flat.cmp_hyp_kind_full;
	unsigned int kind, i;

	/* Every kind cmp_hyp_observe() makes at its cap, at a site the
	 * durable pool holds. */
	hold_site(FULL_NR, SITE_A);
	for (kind = CMP_HYP_EXACT; kind <= CMP_HYP_ENUM_FAMILY; kind++) {
		for (i = 0; i < CMP_HYP_PER_KIND; i++) {
			struct cmp_hypothesis *h = &pool->entries[pool->count++];

			h->kind = kind;
			h->cmp_ip = SITE_A;
			h->width = 4;
		}
		pool->per_kind_count[kind] = CMP_HYP_PER_KIND;
	}
	cmp_hyp_observe(FULL_NR, false, SITE_B, 0x9003, 4);
	if (kcov_shm->cmp_hyp_lifecycle.cmp_hyp_pool_full_by_kind[CMP_HYP_EXACT] != 1 ||
	    kcov_shm->hyp_flat.cmp_hyp_kind_full != kind_full)
		BUG("cmp hyp store: a pool with every kind at its cap was not full");
}

void cmp_hyp_store_self_check(void);
void cmp_hyp_store_self_check(void)
{
	kcov_shm = calloc(1, sizeof(*kcov_shm));
	cmp_hints_shm = calloc(1, sizeof(*cmp_hints_shm));
	if (kcov_shm == NULL || cmp_hints_shm == NULL)
		BUG("cmp hyp store: calloc failed");

	check_range_per_site();
	check_slot_reuse();
	check_full_pool();

	free(cmp_hints_shm);
	free(kcov_shm);
	cmp_hints_shm = NULL;
	kcov_shm = NULL;
}
