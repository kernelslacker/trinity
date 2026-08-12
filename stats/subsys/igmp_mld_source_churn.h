#ifndef _TRINITY_STATS_SUBSYS_IGMP_MLD_SOURCE_CHURN_H
#define _TRINITY_STATS_SUBSYS_IGMP_MLD_SOURCE_CHURN_H

struct igmp_mld_source_churn_stats {
	/* igmp_mld_source_churn childop counters */
	unsigned long runs;		/* total igmp_mld_source_churn invocations */
	unsigned long setup_failed;	/* socket / bind / probe latched */
	unsigned long join_ok;		/* MCAST_JOIN_SOURCE_GROUP accepted */
	unsigned long leave_ok;		/* MCAST_LEAVE_SOURCE_GROUP accepted mid-stream */
	unsigned long block_ok;		/* MCAST_BLOCK_SOURCE accepted (INCLUDE->EXCLUDE flip) */
	unsigned long msfilter_ok;	/* MCAST_MSFILTER bulk replace accepted */
	unsigned long drop_ok;		/* IP_DROP_MEMBERSHIP / IPV6_DROP_MEMBERSHIP accepted */
	unsigned long send_ok;		/* sender datagram returned >0 */
	unsigned long msfilter_get_ok;		 /* MCAST_MSFILTER getsockopt oracle attempted */
	unsigned long msfilter_get_overrun;	 /* getsockopt wrote past declared optlen (guard hit) */
	unsigned long msfilter_get_deep_overrun; /* getsockopt wrote past max_write_sz (alloc boundary) */
	unsigned long msfilter_get_rejected;	 /* getsockopt returned <0 (errno logged) */
	unsigned long igmp_max_msf_raise_fail;	 /* open/write of igmp_max_msf procfs failed */
	unsigned long msfilter_enobufs_v4;	 /* ip_mc_msfilter rejected oversized filter (-ENOBUFS, v4) */
	unsigned long msfilter_enobufs_v6;	 /* ip6_mc_msfilter rejected oversized filter (-ENOBUFS, v6) */
	unsigned long add_source_enobufs;	 /* ip_mc_source sl_count cap hit via IP_ADD_SOURCE_MEMBERSHIP */

	/* Per-arm entry tallies for dead-arm detection (arm_entered == 0
	 * over a full run => drain reports DEAD-ARM: <childop>/<arm>).
	 * Bumped at the very top of each switch-case arm in
	 * igmp_source_iter_v4_race() / mld_source_iter_v6_race(),
	 * before any early-return or outcome path.  Five v4 arms (A-E,
	 * rnd_modulo_u32(5)) and four v6 arms (A-D, iter_idx-derived). */
	unsigned long arm_entered_race_v4_a; /* RACE A: MCAST_LEAVE_SOURCE_GROUP shrink */
	unsigned long arm_entered_race_v4_b; /* RACE B: MCAST_BLOCK_SOURCE INCLUDE->EXCLUDE */
	unsigned long arm_entered_race_v4_c; /* RACE C: MCAST_MSFILTER bulk replace */
	unsigned long arm_entered_race_v4_d; /* RACE D: IP_DROP_MEMBERSHIP full leave */
	unsigned long arm_entered_race_v4_e; /* RACE E: IP_ADD_SOURCE_MEMBERSHIP sl_count walk */
	unsigned long arm_entered_race_v6_a; /* RACE A (v6): MCAST_LEAVE_SOURCE_GROUP shrink */
	unsigned long arm_entered_race_v6_b; /* RACE B (v6): MCAST_BLOCK_SOURCE flip */
	unsigned long arm_entered_race_v6_c; /* RACE C (v6): MCAST_MSFILTER bulk replace */
	unsigned long arm_entered_race_v6_d; /* RACE D (v6): IPV6_DROP_MEMBERSHIP */
};

#endif /* _TRINITY_STATS_SUBSYS_IGMP_MLD_SOURCE_CHURN_H */
