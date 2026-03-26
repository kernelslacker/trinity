#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/sctp.h>
#include "net.h"
#include "random.h"
#include "compat.h"

static const unsigned int sctp_opts[] = {
	SCTP_RTOINFO, SCTP_ASSOCINFO, SCTP_INITMSG, SCTP_NODELAY,
	SCTP_AUTOCLOSE, SCTP_SET_PEER_PRIMARY_ADDR, SCTP_PRIMARY_ADDR, SCTP_ADAPTATION_LAYER,
	SCTP_DISABLE_FRAGMENTS, SCTP_PEER_ADDR_PARAMS, SCTP_DEFAULT_SEND_PARAM, SCTP_EVENTS,
	SCTP_I_WANT_MAPPED_V4_ADDR, SCTP_MAXSEG, SCTP_STATUS, SCTP_GET_PEER_ADDR_INFO,
	SCTP_DELAYED_ACK_TIME, SCTP_CONTEXT, SCTP_FRAGMENT_INTERLEAVE, SCTP_PARTIAL_DELIVERY_POINT,
	SCTP_MAX_BURST, SCTP_AUTH_CHUNK, SCTP_HMAC_IDENT, SCTP_AUTH_KEY,
	SCTP_AUTH_ACTIVE_KEY, SCTP_AUTH_DELETE_KEY, SCTP_PEER_AUTH_CHUNKS, SCTP_LOCAL_AUTH_CHUNKS,
	SCTP_GET_ASSOC_NUMBER, SCTP_GET_ASSOC_ID_LIST, SCTP_AUTO_ASCONF, SCTP_PEER_ADDR_THLDS,

	/* 32-37: added 3.x-4.x era */
	SCTP_RECVRCVINFO, SCTP_RECVNXTINFO, SCTP_DEFAULT_SNDINFO,
	SCTP_AUTH_DEACTIVATE_KEY, SCTP_REUSE_PORT, SCTP_PEER_ADDR_THLDS_V2,

	SCTP_SOCKOPT_BINDX_ADD, SCTP_SOCKOPT_BINDX_REM, SCTP_SOCKOPT_PEELOFF, SCTP_SOCKOPT_CONNECTX_OLD,
	SCTP_GET_PEER_ADDRS, SCTP_GET_LOCAL_ADDRS, SCTP_SOCKOPT_CONNECTX, SCTP_SOCKOPT_CONNECTX3,
	SCTP_GET_ASSOC_STATS,

	/* 113-133: added 4.10-6.7 era */
	SCTP_PR_SUPPORTED, SCTP_DEFAULT_PRINFO, SCTP_PR_ASSOC_STATUS, SCTP_PR_STREAM_STATUS,
	SCTP_RECONFIG_SUPPORTED, SCTP_ENABLE_STREAM_RESET, SCTP_RESET_STREAMS, SCTP_RESET_ASSOC,
	SCTP_ADD_STREAMS, SCTP_SOCKOPT_PEELOFF_FLAGS, SCTP_STREAM_SCHEDULER, SCTP_STREAM_SCHEDULER_VALUE,
	SCTP_INTERLEAVING_SUPPORTED, SCTP_SENDMSG_CONNECT, SCTP_EVENT,
	SCTP_ASCONF_SUPPORTED, SCTP_AUTH_SUPPORTED, SCTP_ECN_SUPPORTED,
	SCTP_EXPOSE_POTENTIALLY_FAILED_STATE, SCTP_REMOTE_UDP_ENCAPS_PORT, SCTP_PLPMTUD_PROBE_INTERVAL,
};

void sctp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	struct sctp_rtoinfo *rtoinfo;
	struct sctp_assocparams *assocparams;
	struct sctp_initmsg *initmsg;
	__u32 *optval32;

	so->optname = RAND_ARRAY(sctp_opts);

	switch (so->optname) {
	case SCTP_RTOINFO:
		rtoinfo = (struct sctp_rtoinfo *) so->optval;
		rtoinfo->srto_assoc_id = rand();
		rtoinfo->srto_initial = rand() % 60000;
		rtoinfo->srto_max = rand() % 60000;
		rtoinfo->srto_min = rand() % 60000;
		so->optlen = sizeof(struct sctp_rtoinfo);
		break;

	case SCTP_ASSOCINFO:
		assocparams = (struct sctp_assocparams *) so->optval;
		assocparams->sasoc_assoc_id = rand();
		assocparams->sasoc_asocmaxrxt = rand();
		assocparams->sasoc_number_peer_destinations = rand();
		assocparams->sasoc_peer_rwnd = rand();
		assocparams->sasoc_local_rwnd = rand();
		assocparams->sasoc_cookie_life = rand();
		so->optlen = sizeof(struct sctp_assocparams);
		break;

	case SCTP_INITMSG:
		initmsg = (struct sctp_initmsg *) so->optval;
		initmsg->sinit_num_ostreams = rand();
		initmsg->sinit_max_instreams = rand();
		initmsg->sinit_max_attempts = rand();
		initmsg->sinit_max_init_timeo = rand();
		so->optlen = sizeof(struct sctp_initmsg);
		break;

	case SCTP_NODELAY:
	case SCTP_DISABLE_FRAGMENTS:
	case SCTP_I_WANT_MAPPED_V4_ADDR:
	case SCTP_AUTO_ASCONF:
	case SCTP_REUSE_PORT:
		optval32 = (__u32 *) so->optval;
		*optval32 = RAND_BOOL();
		so->optlen = sizeof(__u32);
		break;

	default:
		break;
	}
}
