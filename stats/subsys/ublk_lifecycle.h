#ifndef _TRINITY_STATS_SUBSYS_UBLK_LIFECYCLE_H
#define _TRINITY_STATS_SUBSYS_UBLK_LIFECYCLE_H

struct ublk_lifecycle_stats {
	/* ublk_lifecycle childop counters */
	unsigned long iters;		/* per-iteration loop body entries */
	unsigned long eperm;		/* /dev/ublk-control open returned EPERM/ENOENT/ENXIO/EACCES (latched) */
	unsigned long add_ok;		/* UBLK_U_CMD_ADD_DEV via uring_cmd accepted; dev_id assigned */
	unsigned long fetch_ok;		/* UBLK_U_IO_FETCH_REQ submitted on the queue chrdev (parked, non-blocking) */
	unsigned long del_ok;		/* UBLK_U_CMD_DEL_DEV via uring_cmd accepted */
	unsigned long race_observed;	/* FETCH_REQ in flight when DEL_DEV fired (the f7700a4415af window) */
};

#endif /* _TRINITY_STATS_SUBSYS_UBLK_LIFECYCLE_H */
