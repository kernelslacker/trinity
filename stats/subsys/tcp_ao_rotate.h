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
	/* reconnect-to-different-peer arm (peer-change current_key UAF) */
	unsigned long reconnect_attempted;  /* peer-change arm entered */
	unsigned long reconnect_setup_failed; /* listener/key setup failed before connect */
	unsigned long reconnect_failed;	    /* connect() to peer 2 failed (not EINPROGRESS) */
	unsigned long reconnect_ok;	    /* client connect() to peer 2 returned 0 or EINPROGRESS */
	unsigned long reconnect_probed;	    /* UAF probes (TCP_AO_INFO+DEL_KEY on stale key) fired after peer change */
	unsigned long stale_key_probed;	    /* TCP_AO_INFO/DEL_KEY issued after peer change */
	/* vrf-enslave/detach arm (L3-master membership race during connect) */
	unsigned long vrf_enslave_attempted;    /* VRF arm entered: keys installed, connect about to fire */
	unsigned long vrf_enslave_setup_failed; /* VRF/veth/addr/key setup failed before connect */
	unsigned long vrf_ao_unavailable;       /* TCP_AO_ADD_KEY failed (ENOPROTOOPT/EPERM) — host has no TCP-AO */
	unsigned long vrf_detach_raced;         /* detach child opened netlink socket (oracle: reached rtnl path) */
	unsigned long vrf_detach_landed;        /* RTM_SETLINK MASTER=0 accepted by kernel (nl_send_recv == 0) */
	unsigned long vrf_connect_issued;       /* connect() fired on VRF-bound socket (denominator) */
	unsigned long vrf_connect_ok;           /* accept() succeeded: server saw the SYN through VRF */
	unsigned long vrf_accept_timeout;       /* poll() expired before POLLIN: box too busy to accept */
	unsigned long vrf_detach_before_connect; /* per-iter: detach RTM_SETLINK fired before connect() */
	unsigned long vrf_detach_after_connect;  /* per-iter: detach RTM_SETLINK fired after connect() */
	unsigned long vrf_detach_tied;           /* per-iter: detach and connect timestamps equal (d==0) */
	unsigned long vrf_pipe_unavailable;      /* pipe() failed for race_pfd/rendezvous_pfd/ready_pfd; arm skipped */
};

#endif /* _TRINITY_STATS_SUBSYS_TCP_AO_ROTATE_H */
