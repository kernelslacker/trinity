#ifndef _TRINITY_STATS_SUBSYS_UFFD_FAULT_MOVE_H
#define _TRINITY_STATS_SUBSYS_UFFD_FAULT_MOVE_H

struct uffd_fault_move_stats {
	/* variant 1: fault-resolve matrix (COPY/ZEROPAGE/POISON/WP) */
	unsigned long v1_resolve_ok;		/* fault resolved without error */
	unsigned long v1_resolve_fail;		/* resolve ioctl returned -1 */
	unsigned long v1_wp_faults_resolved;	/* WP faults unprotected via UFFDIO_WRITEPROTECT */
	unsigned long v1_poison_faults_resolved;/* MISSING faults resolved with UFFDIO_POISON */
	unsigned long v1_dontwake_still_blocked;/* DONTWAKE: thread stayed blocked until explicit WAKE */
	unsigned long v1_dontwake_woke_early;	/* DONTWAKE: kernel woke thread before WAKE (unexpected) */
	/* variant 2: UFFDIO_MOVE / swap-cache race */
	unsigned long v2_move_ok;		/* UFFDIO_MOVE completed */
	unsigned long v2_move_fail;		/* UFFDIO_MOVE returned -1 (non-EINVAL) */
	unsigned long v2_move_einval;		/* UFFDIO_MOVE returned -EINVAL */
	unsigned long v2_move_skipped;		/* invocation: UFFDIO_MOVE never attempted */
	/* variant 3: teardown race (close/UNREGISTER/munmap racing fault) */
	unsigned long v3_teardown_ok;		/* teardown action issued */
	unsigned long v3_teardown_fail;		/* teardown action failed */
	/* oracle: per-page sequence-number check after MOVE/COPY */
	unsigned long oracle_checks_run;	/* pages checked at destination */
	unsigned long oracle_mismatch;		/* pages with wrong seqno */
};

#endif /* _TRINITY_STATS_SUBSYS_UFFD_FAULT_MOVE_H */
