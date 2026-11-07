/*
 * Self-check for the typed-hypothesis store cmp_hyp_observe() fills: a
 * comparison site keeps one RANGE hypothesis, whose bounds follow the
 * site's cluster as it widens, and a second site that sees the same
 * values keeps its own, since the picker serves a hypothesis only at its
 * own site.
 */

#include <stdint.h>
#include <stdlib.h>

#include "cmp_hints.h"
#include "debug.h"		/* BUG */
#include "kcov.h"

#define STORE_NR	11U
#define SITE_A		0x5150UL
#define SITE_B		0x5151UL

static unsigned int ranges_at(const struct cmp_hyp_pool *pool,
			      unsigned long cmp_ip,
			      const struct cmp_hypothesis **last)
{
	unsigned int i, n = 0;

	for (i = 0; i < pool->count; i++) {
		const struct cmp_hypothesis *h = &pool->entries[i];

		if (h->kind == CMP_HYP_RANGE && h->cmp_ip == cmp_ip) {
			*last = h;
			n++;
		}
	}
	return n;
}

void cmp_hyp_store_self_check(void);
void cmp_hyp_store_self_check(void)
{
	const struct cmp_hypothesis *r = NULL;
	struct cmp_hyp_pool *pool;
	unsigned long v;

	kcov_shm = calloc(1, sizeof(*kcov_shm));
	cmp_hints_shm = calloc(1, sizeof(*cmp_hints_shm));
	if (kcov_shm == NULL || cmp_hints_shm == NULL)
		BUG("cmp hyp store: calloc failed");
	pool = &cmp_hints_shm->hyp_pools[STORE_NR][0];

	/* The third value makes a RANGE, and each one after widens it. */
	for (v = 10; v <= 14; v++) {
		cmp_hyp_observe(STORE_NR, false, SITE_A, v, 4);
		cmp_hyp_observe(STORE_NR, false, SITE_B, v, 4);
	}
	if (ranges_at(pool, SITE_A, &r) != 1 || r->lo != 10 || r->hi != 14)
		BUG("cmp hyp store: a widening site kept a RANGE per step, or stale bounds");
	if (ranges_at(pool, SITE_B, &r) != 1 || r->lo != 10 || r->hi != 14)
		BUG("cmp hyp store: a second site with the same range got none of its own");

	free(cmp_hints_shm);
	free(kcov_shm);
	cmp_hints_shm = NULL;
	kcov_shm = NULL;
}
