#ifndef _TRINITY_STATS_SUBSYS_FDSTRESS_H
#define _TRINITY_STATS_SUBSYS_FDSTRESS_H

struct fdstress_stats {
	/* fd_stress childop counters, one per stress mode */
	unsigned long close_reopen;
	unsigned long dup2_replace;
	unsigned long type_confusion;
	unsigned long cloexec_toggle;
	/* Skipped invocations where the destructive target (the fd being
	 * closed by close(), or the dup2 destination) resolved to a
	 * protected fd -- STDERR_FILENO, the stderr capture memfd, kcov
	 * slots, tainted_fd, or fail_nth_fd.  Counted here so the
	 * suppression is visible in stats output; a runaway skip rate
	 * means the fd pool is dominated by protected slots. */
	unsigned long protected_skipped;
};

#endif /* _TRINITY_STATS_SUBSYS_FDSTRESS_H */
