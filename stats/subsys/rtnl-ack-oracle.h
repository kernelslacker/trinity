#ifndef TRINITY_STATS_SUBSYS_RTNL_ACK_ORACLE_H
#define TRINITY_STATS_SUBSYS_RTNL_ACK_ORACLE_H

/*
 * Per-RTM-group dimension.  RTM messages are grouped by the kernel in
 * blocks of four (NEW/DEL/GET/SET); group = (nlmsg_type - RTM_BASE) / 4.
 * 64 slots covers up to RTM_BASE + 256 message types, well above the
 * current RTM_MAX (~212).  The per-group array name ends in _per_group so
 * the check-stats-reachable walker leaves it in its allowlist (array
 * entries are walked by the custom rtnl_ack_oracle dump renderer, not by
 * STAT_FIELD descriptor rows).
 */
#define RTNL_ACK_ORACLE_MAX_GROUPS 64

struct rtnl_ack_oracle_stats {
	/*
	 * Aggregate outcome histogram across all probed rtnl messages.
	 * The oracle opens a private NETLINK_ROUTE socket, sends the
	 * generated message with NLM_F_ACK forced, reads the NLMSG_ERROR
	 * reply, and classifies err->error into one of these buckets.
	 */
	unsigned long accepted;	  /* err->error == 0: kernel accepted    */
	unsigned long einval;	  /* -EINVAL                              */
	unsigned long erange;	  /* -ERANGE                              */
	unsigned long eopnotsupp; /* -EOPNOTSUPP                          */
	unsigned long eperm;	  /* -EPERM                               */
	unsigned long other;	  /* any other non-zero errno             */
	unsigned long send_fail;  /* socket()/bind()/send() local error   */
	unsigned long no_reply;	  /* recv returned nothing or bad framing */
	/*
	 * Per-RTM-group accepted counter.
	 * index = (nlmsg_type - RTM_BASE) / 4; index in [0, MAX_GROUPS).
	 * A non-zero entry means the oracle confirmed at least one message
	 * of that RTM group was accepted by the kernel; a zero entry means
	 * every probe of that group was rejected or produced no reply.
	 * Emitted by the custom rtnl_ack_oracle dump renderer.
	 */
	unsigned long type_accepted_per_group[RTNL_ACK_ORACLE_MAX_GROUPS];
};

#endif /* TRINITY_STATS_SUBSYS_RTNL_ACK_ORACLE_H */
