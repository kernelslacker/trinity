#ifndef _TRINITY_STATS_SUBSYS_IOURING_H
#define _TRINITY_STATS_SUBSYS_IOURING_H

struct iouring_stats {
	/* iouring_flood childop counters */
	unsigned long runs;		/* total iouring_flood invocations */
	unsigned long submits;		/* SQEs successfully submitted via io_uring_enter */
	unsigned long reaped;		/* CQEs drained from the completion ring */
	unsigned long failed;		/* setup/mmap/submit_burst/io_uring_enter returned -1 */
};

#endif /* _TRINITY_STATS_SUBSYS_IOURING_H */
