#ifndef _TRINITY_STATS_SUBSYS_RECIPE_H
#define _TRINITY_STATS_SUBSYS_RECIPE_H

struct recipe_stats {
	/* recipe_runner childop counters */
	unsigned long runs;		/* total recipe_runner invocations */
	unsigned long completed;		/* full sequence ran without failure */
	unsigned long partial;		/* at least one step failed */
	unsigned long unsupported;	/* discovery probe latched recipe off */
};

#endif /* _TRINITY_STATS_SUBSYS_RECIPE_H */
