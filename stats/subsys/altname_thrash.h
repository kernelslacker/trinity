#ifndef _TRINITY_STATS_SUBSYS_ALTNAME_THRASH_H
#define _TRINITY_STATS_SUBSYS_ALTNAME_THRASH_H

/*
 * altname_thrash childop counters.  Bespoke (non-category) RAW group.
 * All bumps RELAXED on shm->stats.  The surrounding struct stats_s
 * composes an instance of struct altname_thrash_stats as its
 * "altname_thrash" member.
 */
struct altname_thrash_stats {
	unsigned long invocations;	/* total altname_thrash invocations */
	unsigned long unshare_failed;	/* unshare(CLONE_NEWNET) failed (latched) */
	unsigned long addprop_done;	/* RTM_NEWLINKPROP IFLA_PROP_LIST accepted */
	unsigned long delprop_done;	/* RTM_DELLINKPROP IFLA_PROP_LIST accepted */
	unsigned long getlink_done;	/* RTM_GETLINK targeted with RTEXT_FILTER_VF accepted */
};

#endif	/* _TRINITY_STATS_SUBSYS_ALTNAME_THRASH_H */
