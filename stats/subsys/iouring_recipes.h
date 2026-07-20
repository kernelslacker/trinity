#ifndef _TRINITY_STATS_SUBSYS_IOURING_RECIPES_H
#define _TRINITY_STATS_SUBSYS_IOURING_RECIPES_H

/* Upper bound on the iouring_recipes catalog.  iouring-recipes.c asserts
 * at build time that its table fits. */
#define MAX_IOURING_RECIPES 64

struct iouring_recipes_stats {
	/* iouring_recipes childop counters */
	unsigned long runs;		/* total invocations */
	unsigned long completed;	/* recipe completed successfully */
	unsigned long partial;		/* at least one step failed */
	unsigned long enosys;		/* io_uring_setup returned ENOSYS */

	/* Per-iouring-recipe completion counts, indexed by the recipe's slot
	 * in the static catalog inside iouring-recipes.c.  Dumped via
	 * iouring_recipes_dump_stats() so the stats dump stays decoupled from
	 * the catalog layout. */
	unsigned long completed_per[MAX_IOURING_RECIPES];
};

#endif /* _TRINITY_STATS_SUBSYS_IOURING_RECIPES_H */
