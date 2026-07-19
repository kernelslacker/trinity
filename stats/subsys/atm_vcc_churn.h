#ifndef _TRINITY_STATS_SUBSYS_ATM_VCC_CHURN_H
#define _TRINITY_STATS_SUBSYS_ATM_VCC_CHURN_H

struct atm_vcc_churn_stats {
	/* atm_vcc_churn childop counters */
	unsigned long runs;		/* total atm_vcc_churn invocations */
	unsigned long unsupported;	/* socket(AF_ATM*) returned EAFNOSUPPORT (CONFIG_ATM=n) */
	unsigned long socket_ok;		/* AF_ATMPVC/AF_ATMSVC vcc opened */
	unsigned long ioctls_sent;	/* ioctls dispatched against the vcc */
	unsigned long kernel_rejected;	/* ioctl returned <0 (expected without backend) */
};

#endif /* _TRINITY_STATS_SUBSYS_ATM_VCC_CHURN_H */
