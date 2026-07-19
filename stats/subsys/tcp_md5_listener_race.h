#ifndef _TRINITY_STATS_SUBSYS_TCP_MD5_LISTENER_RACE_H
#define _TRINITY_STATS_SUBSYS_TCP_MD5_LISTENER_RACE_H

struct tcp_md5_listener_race_stats {
	/* tcp_md5_listener_race childop counters */
	unsigned long runs;		/* total tcp_md5_listener_race invocations */
	unsigned long setup_failed;	/* loopback listen/socket/bind setup failed */
	unsigned long md5_set_ok;		/* TCP_MD5SIG install/rotate/delete accepted */
	unsigned long md5_set_failed;	/* TCP_MD5SIG rejected (EOPNOTSUPP/EINVAL/EPERM) */
	unsigned long connect_ok;		/* zero-linger client connect() egress observed */
	unsigned long rst_sent_ok;	/* zero-linger close() drove RST toward listener */
	unsigned long completed_ok;	/* full cycles reaching teardown */
};

#endif /* _TRINITY_STATS_SUBSYS_TCP_MD5_LISTENER_RACE_H */
