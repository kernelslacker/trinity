#ifndef _TRINITY_STATS_SUBSYS_IOURING_RECIPES_H
#define _TRINITY_STATS_SUBSYS_IOURING_RECIPES_H

struct iouring_recipes_stats {
	/* iouring_recipes childop counters */
	unsigned long runs;		/* total invocations */
	unsigned long completed;	/* recipe completed successfully */
	unsigned long partial;		/* at least one step failed */
	unsigned long enosys;		/* io_uring_setup returned ENOSYS */
};

#endif /* _TRINITY_STATS_SUBSYS_IOURING_RECIPES_H */
