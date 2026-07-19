#ifndef _TRINITY_STATS_SUBSYS_PACKET_FANOUT_THRASH_H
#define _TRINITY_STATS_SUBSYS_PACKET_FANOUT_THRASH_H

struct packet_fanout_thrash_stats {
	/* packet_fanout_thrash childop counters */
	unsigned long runs;		/* total packet_fanout_thrash invocations */
	unsigned long setup_failed;	/* socket(AF_PACKET) failed (EPERM/no CONFIG_PACKET) */
	unsigned long ring_failed;	/* PACKET_RX_RING setsockopt failed */
	unsigned long rings_installed;	/* successful PACKET_RX_RING install */
	unsigned long mmap_failed;	/* mmap of the RX ring failed */
	unsigned long joins;		/* successful PACKET_FANOUT join */
	unsigned long rejoins_ok;		/* second PACKET_FANOUT setsockopt accepted */
	unsigned long rejoins_rejected;	/* second PACKET_FANOUT rejected (EALREADY etc) */
};

#endif /* _TRINITY_STATS_SUBSYS_PACKET_FANOUT_THRASH_H */
