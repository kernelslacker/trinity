#ifndef _TRINITY_STATS_SUBSYS_PSP_KEY_ROTATE_H
#define _TRINITY_STATS_SUBSYS_PSP_KEY_ROTATE_H

struct psp_key_rotate_stats {
	/* psp_key_rotate childop counters */
	unsigned long runs;			/* total psp_key_rotate invocations */
	unsigned long setup_failed;		/* unshare / netlink open / family probe latched */
	unsigned long netdev_create_ok;		/* rtnl RTM_NEWLINK netdevsim accepted */
	unsigned long family_resolve_ok;		/* CTRL_CMD_GETFAMILY resolved PSP family id */
	unsigned long dev_get_ok;		/* PSP_CMD_DEV_GET dump returned without error */
	unsigned long key_install_ok;		/* initial PSP_CMD_KEY_ROTATE accepted */
	unsigned long spi_set_ok;		/* PSP_CMD_TX_ASSOC bound socket fd to dev (spec: spi_set_ok) */
	unsigned long send_ok;			/* send() over PSP-bound socket returned >0 */
	unsigned long rotate_ok;			/* mid-flow PSP_CMD_KEY_ROTATE accepted (race target) */
	unsigned long spi_switch_ok;		/* mid-flow PSP_CMD_TX_ASSOC re-bind accepted */
	unsigned long shutdown_ok;		/* shutdown(SHUT_RDWR) on PSP-bound socket returned 0 */
	/* psp_key_rotate sub-mode: psp_devlink_port_churn counters */
	unsigned long devlink_port_churn_runs;			/* sub-mode invocations */
	unsigned long devlink_port_churn_port_add_ok;		/* DEVLINK_CMD_PORT_NEW accepted */
	unsigned long devlink_port_churn_port_del_ok;		/* DEVLINK_CMD_PORT_DEL accepted */
	unsigned long devlink_port_churn_vf_spawn_ok;		/* sriov_numvfs write accepted */
	unsigned long devlink_port_churn_unsupported_latched;	/* family resolve / netdevsim spawn latched */
};

#endif /* _TRINITY_STATS_SUBSYS_PSP_KEY_ROTATE_H */
