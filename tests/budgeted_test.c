/*
 * Self-check for BUDGETED(): a childop's iteration budget scales by its
 * adaptive multiplier, which a stray write to the shared stats can leave
 * anywhere in a u16, so the read holds it to the range adapt_budget()
 * keeps: an unset one reads as unity, and the rest as ADAPT_BUDGET_MIN
 * to ADAPT_BUDGET_MAX.
 */

#include <stdint.h>

#include "child.h"		/* BUDGETED, CHILD_OP_XATTR_THRASH */
#include "debug.h"		/* BUG */
#include "shm.h"		/* shm, ADAPT_BUDGET_* */

/* The budget of an op whose fixed budget is 1000, at multiplier @mult. */
static unsigned int budget_at(uint16_t mult)
{
	shm->stats.childop.budget_mult[CHILD_OP_XATTR_THRASH] = mult;
	return BUDGETED(CHILD_OP_XATTR_THRASH, 1000);
}

void budgeted_self_check(void);
void budgeted_self_check(void)
{
	uint16_t saved = shm->stats.childop.budget_mult[CHILD_OP_XATTR_THRASH];

	if (budget_at(0) != 1000)
		BUG("BUDGETED: an unset multiplier is not unity");
	if (budget_at(ADAPT_BUDGET_UNITY * 2) != 2000)
		BUG("BUDGETED: a multiplier in range is not applied");
	if (budget_at(UINT16_MAX) != 1000 * ADAPT_BUDGET_MAX / ADAPT_BUDGET_UNITY)
		BUG("BUDGETED: a multiplier past ADAPT_BUDGET_MAX is not held to it");
	if (budget_at(1) != 1000 * ADAPT_BUDGET_MIN / ADAPT_BUDGET_UNITY)
		BUG("BUDGETED: a multiplier under ADAPT_BUDGET_MIN is not held to it");

	shm->stats.childop.budget_mult[CHILD_OP_XATTR_THRASH] = saved;
}
