#ifndef _TRINITY_STATS_SUBSYS_UFFD_H
#define _TRINITY_STATS_SUBSYS_UFFD_H

struct uffd_stats {
	/* uffd_churn childop counters */
	unsigned long runs;		/* total uffd_churn invocations */
	unsigned long registers;		/* successful UFFDIO_REGISTER */
	unsigned long unregisters;		/* successful UFFDIO_UNREGISTER */
	unsigned long failed;		/* userfaultfd/UFFDIO_API/mmap/REGISTER/UNREGISTER returned -1 */
};

#endif /* _TRINITY_STATS_SUBSYS_UFFD_H */
