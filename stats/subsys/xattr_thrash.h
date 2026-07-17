#ifndef _TRINITY_STATS_SUBSYS_XATTR_THRASH_H
#define _TRINITY_STATS_SUBSYS_XATTR_THRASH_H

/* xattr_thrash childop counters */
struct xattr_thrash_stats {
	unsigned long runs;	/* total xattr_thrash invocations */
	unsigned long set;	/* successful set/fsetxattr calls */
	unsigned long get;	/* successful get/fgetxattr calls */
	unsigned long remove;	/* successful remove/fremovexattr calls */
	unsigned long list;	/* successful list/flistxattr calls */
	unsigned long failed;	/* any xattr syscall returned -1 */
};

#endif /* _TRINITY_STATS_SUBSYS_XATTR_THRASH_H */
