#ifndef _TRINITY_STATS_SUBSYS_MEMFD_SECRET_LIFECYCLE_H
#define _TRINITY_STATS_SUBSYS_MEMFD_SECRET_LIFECYCLE_H

/*
 * Per-run counters for the memfd_secret_lifecycle childop.
 *
 * oracle_pass           -- cross-process reads correctly denied by secretmem.
 * oracle_fired          -- cross-process reads incorrectly succeeded (kernel
 *                          bug: secret memory readable via process_vm_readv
 *                          or /proc/pid/mem).
 * oracle_inconclusive   -- oracle skipped because the ambient environment
 *                          (Yama, non-dumpable, no secretmem on this kernel)
 *                          denied even the anon positive-control read, making
 *                          it impossible to attribute a denial to secretmem.
 * conc_truncate_races   -- concurrent ftruncate(0)/ftruncate(size)
 *                          round-trips completed by the truncate-race thread.
 * setup_rejected        -- memfd_secret(2) returned ENOSYS or EINVAL
 *                          (CONFIG_SECRETMEM=n or disabled at runtime).
 */
struct memfd_secret_lifecycle_stats {
	unsigned long oracle_pass;
	unsigned long oracle_fired;
	unsigned long oracle_inconclusive;
	unsigned long conc_truncate_races;
	unsigned long setup_rejected;
};

#endif /* _TRINITY_STATS_SUBSYS_MEMFD_SECRET_LIFECYCLE_H */
