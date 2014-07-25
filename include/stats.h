#pragma once

/* Various statistics. */

struct stats_s {
	unsigned long total_syscalls_done;
	unsigned long successes;
	unsigned long failures;

	/* Counts to tell if we're making progress or not. */
	unsigned long previous_op_count;	/* combined total of all children */
};
