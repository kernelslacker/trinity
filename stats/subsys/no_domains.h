#ifndef _TRINITY_STATS_SUBSYS_NO_DOMAINS_H
#define _TRINITY_STATS_SUBSYS_NO_DOMAINS_H

struct no_domains_stats {
	/* Number of socket families auto-marked in no_domains[] at startup
	 * because socket() probes returned EAFNOSUPPORT/EPROTONOSUPPORT for
	 * both SOCK_STREAM and SOCK_DGRAM.  Bumped once per latched PF from
	 * open_sockets().  A non-zero value tells the operator how many
	 * random-syscall socket() picks per cycle the kernel build can
	 * never reach -- and confirms the auto-skip ran (vs. the user
	 * supplying --exclude-domains by hand). */
	unsigned long runtime_skipped;
};

#endif /* _TRINITY_STATS_SUBSYS_NO_DOMAINS_H */
