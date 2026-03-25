#pragma once

/* Various statistics. */

struct stats_s {
	unsigned long op_count;
	unsigned long successes;
	unsigned long failures;

	/* Counts to tell if we're making progress or not. */
	unsigned long previous_op_count;	/* combined total of all children */

	/* fd lifecycle tracking */
	unsigned long fd_stale_detected;
	unsigned long fd_stale_by_generation;
	unsigned long fd_closed_tracked;
	unsigned long fd_regenerated;
	unsigned long fd_duped;
};

void dump_stats(void);
