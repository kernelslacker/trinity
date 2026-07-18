#ifndef _TRINITY_STATS_SUBSYS_STATMOUNT_IDMAP_H
#define _TRINITY_STATS_SUBSYS_STATMOUNT_IDMAP_H

struct statmount_idmap_stats {
	/* statmount_idmap_overflow childop counters */
	unsigned long runs;			/* total statmount_idmap_overflow invocations */
	unsigned long setup_failed;		/* syscall probe / ns unshare / scratch alloc latch fired */
	unsigned long iter;			/* outer-loop iterations entered */
	unsigned long fork_failed;		/* fork() of the carrier userns helper failed */
	unsigned long carrier_ok;		/* carrier userns built + fd pinned */
	unsigned long carrier_fail;		/* carrier userns setup failed (setgroups/map write/open) */
	unsigned long setattr_ok;		/* mount_setattr(MOUNT_ATTR_IDMAP) accepted on detached mount */
	unsigned long setattr_fail;		/* mount_setattr(MOUNT_ATTR_IDMAP) rejected */
	unsigned long statmount_call;		/* statmount() calls issued across the bufsize sweep */
	unsigned long statmount_ok;		/* statmount() returned 0 (full render fit) */
	unsigned long statmount_overflow;	/* statmount() returned -EOVERFLOW (seq-buffer truncation path) */
};

#endif /* _TRINITY_STATS_SUBSYS_STATMOUNT_IDMAP_H */
