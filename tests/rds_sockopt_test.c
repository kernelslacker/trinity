/*
 * Self-check for the RDS option builder: rds_setsockopt() (net/rds/af_rds.c)
 * turns a flag option on for any int but 0, takes SO_RDS_TRANSPORT's TCP
 * in any netns and IB in the initial one, and takes up to
 * RDS_MSG_RX_DGRAM_TRACE_MAX latency trace points, each below it, so the
 * flags drawn turn both on and off, both transports are drawn, and most
 * latency traces drawn turn tracing on.
 */

#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>

#include "debug.h"		/* BUG */
#include "kernel/rds.h"		/* RDS_*, struct rds_rx_trace_so */
#include "net.h"		/* proto_rds, struct sockopt */

#define RDS_ROUNDS	6000
#define RDS_OPTVAL_LEN	4096

static bool tracing_on(const struct sockopt *so)
{
	const struct rds_rx_trace_so *trace =
		(const struct rds_rx_trace_so *) so->optval;
	unsigned int i;

	if (so->optlen != sizeof(*trace) || trace->rx_traces == 0 ||
	    trace->rx_traces > RDS_MSG_RX_DGRAM_TRACE_MAX)
		return false;
	for (i = 0; i < trace->rx_traces; i++) {
		if (trace->rx_trace_pos[i] >= RDS_MSG_RX_DGRAM_TRACE_MAX)
			return false;
	}
	return true;
}

void rds_sockopt_self_check(void);
void rds_sockopt_self_check(void)
{
	struct socket_triplet rds = {
		.family = PF_RDS, .type = SOCK_SEQPACKET,
	};
	static unsigned char optval[RDS_OPTVAL_LEN];
	unsigned int i, on = 0, off = 0, tcp = 0, ib = 0;
	unsigned int traces = 0, traced = 0;

	for (i = 0; i < RDS_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		unsigned int val;

		memset(optval, 0, sizeof(optval));
		proto_rds.setsockopt(&so, &rds);
		memcpy(&val, optval, sizeof(val));

		switch (so.optname) {
		case RDS_RECVERR:
		case RDS_CONG_MONITOR:
		case SO_TIMESTAMP_OLD:
		case SO_TIMESTAMP_NEW:
			if (val != 0)
				on++;
			else
				off++;
			break;
		case SO_RDS_TRANSPORT:
			if (val == RDS_TRANS_TCP)
				tcp++;
			else if (val == RDS_TRANS_IB)
				ib++;
			break;
		case SO_RDS_MSG_RXPATH_LATENCY:
			traces++;
			if (tracing_on(&so))
				traced++;
			break;
		}
	}

	if (on == 0 || off == 0)
		BUG("rds: the flag options never turn both on and off");
	if (tcp == 0 || ib == 0)
		BUG("rds: a transport rds_set_transport() takes is never drawn");
	if (traces == 0 || traced < traces / 2)
		BUG("rds: the latency traces that turn tracing on are rare");
}
