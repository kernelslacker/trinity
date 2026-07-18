#ifndef _TRINITY_STATS_SUBSYS_SETSOCKOPT_PAIRING_H
#define _TRINITY_STATS_SUBSYS_SETSOCKOPT_PAIRING_H

struct setsockopt_pairing_stats {
	/* setsockopt pairing: dependent-option pairs fired on same fd */
	unsigned long paired_emitted;
};

#endif /* _TRINITY_STATS_SUBSYS_SETSOCKOPT_PAIRING_H */
