#ifndef _TRINITY_STATS_SUBSYS_IOURING_EVENTFD_H
#define _TRINITY_STATS_SUBSYS_IOURING_EVENTFD_H

struct iouring_eventfd_stats {
	/* iouring eventfd recursive completion recipe counters */
	unsigned long register_ok;	/* IORING_REGISTER_EVENTFD[_ASYNC] succeeded */
	unsigned long register_fail;	/* register call returned an error */
	unsigned long recursive_runs;	/* recipe ran past register */
	unsigned long recursive_cqes;	/* CQEs reaped within the recipe */
};

#endif /* _TRINITY_STATS_SUBSYS_IOURING_EVENTFD_H */
