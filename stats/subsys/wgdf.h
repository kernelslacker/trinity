#ifndef _TRINITY_STATS_SUBSYS_WGDF_H
#define _TRINITY_STATS_SUBSYS_WGDF_H

struct wgdf_stats {
	/* wireguard_decrypt_flood childop counters */
	unsigned long runs;				/* total wireguard_decrypt_flood invocations */
	unsigned long setup_failed;			/* setup couldn't complete (transient: bind race etc.) */
	unsigned long packets_sent;			/* MESSAGE_DATA frames pushed at wg0 listen port */
	unsigned long unsupported_latched;			/* WIREGUARD module / family absent — op latched off */
};

#endif /* _TRINITY_STATS_SUBSYS_WGDF_H */
