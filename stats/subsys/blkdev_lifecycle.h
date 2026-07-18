#ifndef _TRINITY_STATS_SUBSYS_BLKDEV_LIFECYCLE_H
#define _TRINITY_STATS_SUBSYS_BLKDEV_LIFECYCLE_H

struct blkdev_lifecycle_stats {
	/* blkdev_lifecycle_race childop counters */
	unsigned long runs;			/* total blkdev_lifecycle_race invocations */
	unsigned long setup_failed;		/* /dev/loop0 probe failed (latched if persistent) */
	unsigned long set_fd_ok;		/* LOOP_SET_FD bound a backing file */
	unsigned long clr_fd;			/* LOOP_CLR_FD ran (post-cycle teardown) */
	unsigned long ebusy;			/* LOOP_SET_FD raced sibling: EBUSY/ENXIO/EPERM */
	unsigned long rescans;			/* BLKRRPART issued from rescan thread */
};

#endif /* _TRINITY_STATS_SUBSYS_BLKDEV_LIFECYCLE_H */
