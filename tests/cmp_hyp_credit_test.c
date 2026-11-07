/*
 * Self-check for the typed-hypothesis credit the consume stash feeds:
 * only a pull the live inject arm produced counts toward a hypothesis's
 * consumed denominator, the same pulls its outcome credit counts.
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

static void stash(bool hyp_injected)
{
	cmp_hints_stash_consumed(CREDIT_NR, false, CMP_HINT_POOL_PER_SYSCALL,
				 CMP_HINT_CALLSITE_ARG_OP, CREDIT_IP,
				 CREDIT_VALUE, 4, CMP_HINT_EXACT, false, 0,
				 hyp_injected, false);
}

void cmp_hyp_credit_self_check(void);
void cmp_hyp_credit_self_check(void)
{
	struct childdata *child;
	struct cmp_hyp_pool *pool;
	struct cmp_hypothesis *exact;

	kcov_shm = calloc(1, sizeof(*kcov_shm));
	cmp_hints_shm = calloc(1, sizeof(*cmp_hints_shm));
	child = calloc(1, sizeof(*child));
	if (kcov_shm == NULL || cmp_hints_shm == NULL || child == NULL)
		BUG("cmp hyp credit: calloc failed");
	fake_this_child = child;

	pool = &cmp_hints_shm->hyp_pools[CREDIT_NR][0];
	exact = &pool->entries[pool->count++];
	exact->kind = CMP_HYP_EXACT;
	exact->cmp_ip = CREDIT_IP;
	exact->width = 4;
	exact->exemplar = CREDIT_VALUE;

	/* A raw pull that happens to carry the hypothesis's value. */
	stash(false);
	if (exact->consumed_count != 0)
		BUG("cmp hyp credit: a raw pull counted as a typed consume");
	stash(true);
	if (exact->consumed_count != 1)
		BUG("cmp hyp credit: a typed pull did not count as a consume");

	fake_this_child = NULL;
	free(child);
	free(cmp_hints_shm);
	free(kcov_shm);
	cmp_hints_shm = NULL;
	kcov_shm = NULL;
}
