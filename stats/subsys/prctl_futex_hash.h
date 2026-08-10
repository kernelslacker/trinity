#ifndef _TRINITY_STATS_SUBSYS_PRCTL_FUTEX_HASH_H
#define _TRINITY_STATS_SUBSYS_PRCTL_FUTEX_HASH_H

/* prctl PR_FUTEX_HASH sanitiser counters */
struct prctl_futex_hash_stats {
	unsigned long set_slots_ebusy; /* PR_FUTEX_HASH_SET_SLOTS returned -EBUSY: mm already pivoted to global hash (absorbing state) */
};

#endif /* _TRINITY_STATS_SUBSYS_PRCTL_FUTEX_HASH_H */
