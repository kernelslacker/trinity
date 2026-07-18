#ifndef _TRINITY_STATS_SUBSYS_DEEP_PATH_H
#define _TRINITY_STATS_SUBSYS_DEEP_PATH_H

struct deep_path_stats {
	/* deep_path_nesting childop counters */
	unsigned long runs;				/* total deep_path_nesting invocations */
	unsigned long setup_failed;			/* scratch base create/enter failed; unsupported latch fired */
	unsigned long max_depth_reached;		/* iterations that hit the requested target depth */
	unsigned long reader_ok;			/* reader pass returned successfully */
	unsigned long reader_failed;			/* reader pass returned an error */
};

#endif /* _TRINITY_STATS_SUBSYS_DEEP_PATH_H */
