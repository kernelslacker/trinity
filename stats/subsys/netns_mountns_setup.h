#ifndef _TRINITY_STATS_SUBSYS_NETNS_MOUNTNS_SETUP_H
#define _TRINITY_STATS_SUBSYS_NETNS_MOUNTNS_SETUP_H

struct netns_mountns_setup_stats {
	/* netns_mountns_setup_probe childop counters */
	unsigned long runs;			/* total netns_mountns_setup_probe invocations */
	unsigned long setup_failed;		/* userns_run_in_ns fork/EPERM latch / per-iter unshare failure */
	unsigned long unshare_ok;		/* per-iter unshare(CLONE_NEWNET|CLONE_NEWNS) into fresh nested ns */
	unsigned long mount_private_ok;	/* MS_REC|MS_PRIVATE remount of '/' inside fresh mount ns */
	unsigned long loopback_ok;		/* rtnl bring-up of loopback inside fresh net ns */
	unsigned long socket_ok;		/* first AF_INET socket alloc inside fresh net ns */
	unsigned long completed_ok;		/* full iter reached end of setup sequence */
};

#endif /* _TRINITY_STATS_SUBSYS_NETNS_MOUNTNS_SETUP_H */
