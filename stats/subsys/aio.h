#ifndef _TRINITY_STATS_SUBSYS_AIO_H
#define _TRINITY_STATS_SUBSYS_AIO_H

struct aio_stats {
	/* post_io_submit positive-attribution: iocbs the kernel accepted on
	 * the success branch (retval > 0 and within the [0, nr] bound).
	 * Distinguishes "io_submit doing useful work" from "io_submit mostly
	 * returning -EINVAL"; without it canary work cannot tell a quiet
	 * success window from a quiet rejection window. */
	unsigned long submitted;
};

#endif /* _TRINITY_STATS_SUBSYS_AIO_H */
