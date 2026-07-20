#ifndef _TRINITY_STATS_SUBSYS_RECIPE_H
#define _TRINITY_STATS_SUBSYS_RECIPE_H

/* Upper bound on the recipe_runner catalog size.  recipe-runner.c
 * asserts at startup that its table fits.  Sized large enough to
 * accommodate future recipes without reshuffling shared memory. */
#define MAX_RECIPES 36

struct recipe_stats {
	/* recipe_runner childop counters */
	unsigned long runs;		/* total recipe_runner invocations */
	unsigned long completed;		/* full sequence ran without failure */
	unsigned long partial;		/* at least one step failed */
	unsigned long unsupported;	/* discovery probe latched recipe off */

	/* Per-recipe completion counts, indexed by the recipe's slot in the
	 * static catalog inside recipe-runner.c.  Dumped via
	 * recipe_runner_dump_stats() so the stats dump stays decoupled from the
	 * catalog layout. */
	unsigned long completed_per[MAX_RECIPES];
};

#endif /* _TRINITY_STATS_SUBSYS_RECIPE_H */
