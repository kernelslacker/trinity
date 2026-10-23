/*
 * Self-check for run_fd_provider_replenish() (fds/fds.c): with more eligible
 * providers than REPLENISH_MAX_PROVIDERS_PER_TICK, every working tick serves
 * exactly that many and the walk moves on between ticks, so providers past
 * the first few are reached.  An ineligible one (never initialised, or with
 * no hook) must not use up a tick's cap.  Fakes run on the real registry.
 */

#include <stdbool.h>

#include "debug.h"		/* BUG */
#include "fd.h"
#include "fds/fds-internal.h"
#include "list.h"
#include "utils-macros.h"	/* ARRAY_SIZE, min, max */

#define NR_SERVED	10
#define NEVER_INIT	NR_SERVED
#define NO_HOOK		(-1)
#define BUDGET		7	/* not what run_fd_provider_child_ops() passes */
#define NR_TICKS	200

static unsigned int calls[NR_SERVED + 1];
static unsigned int budget_seen[NR_SERVED + 1];
static unsigned int total_calls;

#define FAKES(X) X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7) X(8) X(9) X(10)

#define DEFINE_FAKE(n)							\
	static void fake_replenish_##n(unsigned int budget)		\
	{								\
		calls[n]++;						\
		budget_seen[n] = budget;				\
		total_calls++;						\
	}
FAKES(DEFINE_FAKE)

#define FAKE_FN(n) fake_replenish_##n,
static void (*const hooks[])(unsigned int) = { FAKES(FAKE_FN) };

/* Registration order is list order: the ineligible two sit among the rest. */
static const struct {
	const char *name;
	int hook;
	bool initialized;
} layout[] = {
	{ "p0", 0, true }, { "p1", 1, true }, { "uninit", NEVER_INIT, false },
	{ "p2", 2, true }, { "p3", 3, true }, { "nohook", NO_HOOK, true },
	{ "p4", 4, true }, { "p5", 5, true }, { "p6", 6, true },
	{ "p7", 7, true }, { "p8", 8, true }, { "p9", 9, true },
};

void fd_replenish_self_check(void);
void fd_replenish_self_check(void)
{
	unsigned int i, ticks, spins = 0, lo, hi;
	struct list_head *node;

	for (i = 0; i < ARRAY_SIZE(layout); i++) {
		struct fd_provider proto = { .name = layout[i].name };

		if (layout[i].hook != NO_HOOK)
			proto.try_replenish = hooks[layout[i].hook];
		register_fd_provider(&proto);
	}
	i = 0;
	list_for_each(node, &fd_providers->list)
		((struct fd_provider *) node)->initialized = layout[i++].initialized;

	for (ticks = 0; ticks < NR_TICKS; ) {
		unsigned int before = total_calls, served;

		run_fd_provider_replenish(BUDGET);
		served = total_calls - before;
		if (served != 0 && served != REPLENISH_MAX_PROVIDERS_PER_TICK)
			BUG("replenish: a tick did not serve exactly the cap");
		if (served != 0)
			ticks++;
		if (++spins > 100 * NR_TICKS)
			BUG("replenish: the rate-limit gate never opened");
	}

	if (calls[NEVER_INIT] != 0)
		BUG("replenish: served a provider that never initialised");

	lo = hi = calls[0];
	for (i = 0; i < NR_SERVED; i++) {
		if (calls[i] == 0)
			BUG("replenish: a provider was never served");
		if (budget_seen[i] != BUDGET)
			BUG("replenish: the per-provider budget was not passed on");
		lo = min(lo, calls[i]);
		hi = max(hi, calls[i]);
	}
	if (hi - lo > 1)
		BUG("replenish: providers were not served in turn");
}
