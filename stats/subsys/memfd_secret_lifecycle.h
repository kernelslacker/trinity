#ifndef _TRINITY_STATS_SUBSYS_MEMFD_SECRET_LIFECYCLE_H
#define _TRINITY_STATS_SUBSYS_MEMFD_SECRET_LIFECYCLE_H

/*
 * Per-run counters for the memfd_secret_lifecycle childop.
 *
 * oracle_pass        -- negative cross-process reads that correctly returned
 *                       EPERM/EIO (confidentiality enforced as expected).
 * oracle_fired       -- negative cross-process reads that incorrectly
 *                       succeeded (kernel bug: secret memory readable via
 *                       process_vm_readv or /proc/pid/mem).
 * conc_truncate_races -- concurrent ftruncate(0)/ftruncate(size) round-trips
 *                       completed by the truncate-race thread.
 * setup_rejected     -- invocations where memfd_secret(2) returned ENOSYS or
 *                       EINVAL (CONFIG_SECRETMEM=n or disabled at runtime).
 */
struct memfd_secret_lifecycle_stats {
	unsigned long oracle_pass;
	unsigned long oracle_fired;
	unsigned long conc_truncate_races;
	unsigned long setup_rejected;
};

#endif /* _TRINITY_STATS_SUBSYS_MEMFD_SECRET_LIFECYCLE_H */
