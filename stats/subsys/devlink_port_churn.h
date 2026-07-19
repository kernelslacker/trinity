#ifndef _TRINITY_STATS_SUBSYS_DEVLINK_PORT_CHURN_H
#define _TRINITY_STATS_SUBSYS_DEVLINK_PORT_CHURN_H

struct devlink_port_churn_stats {
	/* devlink_port_churn childop counters */
	unsigned long iterations;		/* per-loop iteration completed */
	unsigned long split_ok;		/* DEVLINK_CMD_PORT_SPLIT ack 0 */
	unsigned long split_fail;		/* DEVLINK_CMD_PORT_SPLIT non-zero ack (expected sometimes) */
	unsigned long reload_ok;		/* DEVLINK_CMD_RELOAD action=DRIVER_REINIT ack 0 */
	unsigned long reload_fail;		/* DEVLINK_CMD_RELOAD non-zero ack */
	unsigned long create_skipped;	/* netdevsim absent / sysfs unwritable */
};

#endif /* _TRINITY_STATS_SUBSYS_DEVLINK_PORT_CHURN_H */
