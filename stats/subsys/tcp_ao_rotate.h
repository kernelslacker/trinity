#ifndef _TRINITY_STATS_SUBSYS_TCP_AO_ROTATE_H
#define _TRINITY_STATS_SUBSYS_TCP_AO_ROTATE_H

struct tcp_ao_rotate_stats {
	/* tcp_ao_rotate childop counters */
	unsigned long runs;		/* total tcp_ao_rotate invocations */
	unsigned long setup_failed;	/* loopback listen/socket/bind setup failed */
	unsigned long addkey_rejected;	/* TCP_AO_ADD_KEY rejected (ENOPROTOOPT/EPERM/EINVAL/EEXIST) */
	unsigned long keys_added;		/* TCP_AO_ADD_KEY accepted (initial install + per-rotate add) */
	unsigned long connect_failed;	/* connect/accept failed after keys installed */
	unsigned long connected;		/* AO-protected pair reached ESTABLISHED */
	unsigned long packets_sent;	/* send() through AO sign path returned >0 */
	unsigned long key_rotations;	/* TCP_AO_INFO current_key flip accepted */
	unsigned long info_rejected;	/* TCP_AO_INFO rotate rejected (EINVAL etc) */
	unsigned long key_dels;		/* TCP_AO_DEL_KEY accepted (race window vs verify path) */
	unsigned long delkey_rejected;	/* TCP_AO_DEL_KEY rejected */
	unsigned long cycles;		/* full cycles reaching teardown */
};

#endif /* _TRINITY_STATS_SUBSYS_TCP_AO_ROTATE_H */
