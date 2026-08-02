#ifndef _TRINITY_STATS_SUBSYS_XFRM_COMPAT_H
#define _TRINITY_STATS_SUBSYS_XFRM_COMPAT_H

struct xfrm_compat_stats {
	unsigned long sweep_runs;	/* xfrm_compat_msg_sweep sub-mode invocations */
	unsigned long sends_ok;		/* sweep sendto returned >= 0 */
	unsigned long sends_failed;	/* sweep sendto returned < 0 */
	unsigned long replies_seen;	/* sweep recv returned > 0 */
	/*
	 * int-0x80 ALLOCSPI compat lane.  Drives XFRM_MSG_ALLOCSPI through
	 * the ia32 compat entry so alloc_compat() runs against the request
	 * as well as against the dump_one_state() response, exercising the
	 * double-translate 4-byte OOB read in xfrm_alloc_userspi() where a
	 * 228-byte compat xfrm_userspi_info is re-interpreted as the
	 * 232-byte native layout.
	 */
	unsigned long allocspi_runs;		/* allocspi compat lane invocations */
	unsigned long allocspi_sends_ok;	/* int-0x80 sendto returned >= 0 */
	unsigned long allocspi_sends_failed;	/* int-0x80 sendto returned < 0 */
	unsigned long allocspi_replies_seen;	/* follow-up recv returned > 0 */
	unsigned long allocspi_unsupported;	/* int-0x80 gate returned ENOSYS */
};

#endif /* _TRINITY_STATS_SUBSYS_XFRM_COMPAT_H */
