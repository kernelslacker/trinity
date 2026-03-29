#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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
	struct sctp_assoc_value *av;
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

	case SCTP_AUTOCLOSE:
		optval32 = (__u32 *) so->optval;
		*optval32 = rand() % 3600;
		so->optlen = sizeof(__u32);
		break;

	case SCTP_FRAGMENT_INTERLEAVE:
		optval32 = (__u32 *) so->optval;
		*optval32 = rand() % 3;
		so->optlen = sizeof(__u32);
		break;

	case SCTP_PARTIAL_DELIVERY_POINT:
		optval32 = (__u32 *) so->optval;
		*optval32 = 1024 * (1 + rand() % 128);
		so->optlen = sizeof(__u32);
		break;

	case SCTP_ADAPTATION_LAYER: {
		struct sctp_setadaptation *adapt = (struct sctp_setadaptation *) so->optval;
		adapt->ssb_adaptation_ind = rand();
		so->optlen = sizeof(struct sctp_setadaptation);
		break;
	}

	case SCTP_SET_PEER_PRIMARY_ADDR: {
		struct sctp_setpeerprim *pp = (struct sctp_setpeerprim *) so->optval;
		memset(pp, 0, sizeof(*pp));
		pp->sspp_assoc_id = rand();
		so->optlen = sizeof(struct sctp_setpeerprim);
		break;
	}

	case SCTP_PRIMARY_ADDR: {
		struct sctp_prim *prim = (struct sctp_prim *) so->optval;
		memset(prim, 0, sizeof(*prim));
		prim->ssp_assoc_id = rand();
		so->optlen = sizeof(struct sctp_prim);
		break;
	}

	case SCTP_DEFAULT_SEND_PARAM: {
		struct sctp_sndrcvinfo *sinfo = (struct sctp_sndrcvinfo *) so->optval;
		sinfo->sinfo_stream = rand() % 65535;
		sinfo->sinfo_ssn = 0;
		sinfo->sinfo_flags = rand() & 0x010f;
		sinfo->sinfo_ppid = rand();
		sinfo->sinfo_context = rand();
		sinfo->sinfo_timetolive = rand() % 60000;
		sinfo->sinfo_tsn = 0;
		sinfo->sinfo_cumtsn = 0;
		sinfo->sinfo_assoc_id = rand();
		so->optlen = sizeof(struct sctp_sndrcvinfo);
		break;
	}

	case SCTP_DEFAULT_SNDINFO: {
		struct sctp_sndinfo *sndinfo = (struct sctp_sndinfo *) so->optval;
		sndinfo->snd_sid = rand() % 65535;
		sndinfo->snd_flags = rand() & 0x010f;
		sndinfo->snd_ppid = rand();
		sndinfo->snd_context = rand();
		sndinfo->snd_assoc_id = rand();
		so->optlen = sizeof(struct sctp_sndinfo);
		break;
	}

	case SCTP_EVENTS:
		generate_rand_bytes((unsigned char *) so->optval, sizeof(struct sctp_event_subscribe));
		so->optlen = sizeof(struct sctp_event_subscribe);
		break;

	case SCTP_PEER_ADDR_PARAMS: {
		struct sctp_paddrparams *pp = (struct sctp_paddrparams *) so->optval;
		memset(pp, 0, sizeof(*pp));
		pp->spp_assoc_id = rand();
		pp->spp_hbinterval = rand() % 30000;
		pp->spp_pathmaxrxt = rand() % 12;
		pp->spp_pathmtu = rand() % 65536;
		pp->spp_sackdelay = rand() % 500;
		pp->spp_flags = rand() & (SPP_HB_ENABLE | SPP_PMTUD_ENABLE | SPP_SACKDELAY_ENABLE);
		so->optlen = sizeof(struct sctp_paddrparams);
		break;
	}

	case SCTP_AUTH_CHUNK: {
		struct sctp_authchunk *authchunk = (struct sctp_authchunk *) so->optval;
		authchunk->sauth_chunk = rand() & 0xff;
		so->optlen = sizeof(struct sctp_authchunk);
		break;
	}

	case SCTP_HMAC_IDENT: {
		static const __u16 hmac_ids[] = { SCTP_AUTH_HMAC_ID_SHA1, SCTP_AUTH_HMAC_ID_SHA256 };
		struct sctp_hmacalgo *hmac = (struct sctp_hmacalgo *) so->optval;
		unsigned int n = 1 + (rand() % 4);
		unsigned int i;
		hmac->shmac_num_idents = n;
		for (i = 0; i < n; i++)
			hmac->shmac_idents[i] = hmac_ids[rand() % 2];
		so->optlen = sizeof(struct sctp_hmacalgo) + n * sizeof(__u16);
		break;
	}

	case SCTP_AUTH_KEY: {
		struct sctp_authkey *authkey = (struct sctp_authkey *) so->optval;
		unsigned int keylen = rand() % 64;
		authkey->sca_assoc_id = rand();
		authkey->sca_keynumber = rand() % 8;
		authkey->sca_keylength = keylen;
		generate_rand_bytes(authkey->sca_key, keylen);
		so->optlen = sizeof(struct sctp_authkey) + keylen;
		break;
	}

	case SCTP_AUTH_ACTIVE_KEY:
	case SCTP_AUTH_DELETE_KEY:
	case SCTP_AUTH_DEACTIVATE_KEY: {
		struct sctp_authkeyid *keyid = (struct sctp_authkeyid *) so->optval;
		keyid->scact_assoc_id = rand();
		keyid->scact_keynumber = rand() % 8;
		so->optlen = sizeof(struct sctp_authkeyid);
		break;
	}

	case SCTP_DELAYED_ACK_TIME: {
		struct sctp_sack_info *sack = (struct sctp_sack_info *) so->optval;
		sack->sack_assoc_id = rand();
		sack->sack_delay = rand() % 500;
		sack->sack_freq = 1 + (rand() % 8);
		so->optlen = sizeof(struct sctp_sack_info);
		break;
	}

	case SCTP_CONTEXT:
	case SCTP_MAXSEG:
	case SCTP_MAX_BURST:
	case SCTP_PR_SUPPORTED:
	case SCTP_RECONFIG_SUPPORTED:
	case SCTP_ENABLE_STREAM_RESET:
	case SCTP_INTERLEAVING_SUPPORTED:
	case SCTP_SENDMSG_CONNECT:
	case SCTP_ASCONF_SUPPORTED:
	case SCTP_AUTH_SUPPORTED:
	case SCTP_ECN_SUPPORTED:
	case SCTP_EXPOSE_POTENTIALLY_FAILED_STATE:
		av = (struct sctp_assoc_value *) so->optval;
		av->assoc_id = rand();
		av->assoc_value = rand();
		so->optlen = sizeof(struct sctp_assoc_value);
		break;

	case SCTP_STREAM_SCHEDULER: {
		av = (struct sctp_assoc_value *) so->optval;
		av->assoc_id = rand();
		av->assoc_value = rand() % (SCTP_SS_MAX + 1);
		so->optlen = sizeof(struct sctp_assoc_value);
		break;
	}

	case SCTP_STREAM_SCHEDULER_VALUE: {
		struct sctp_stream_value *sv = (struct sctp_stream_value *) so->optval;
		sv->assoc_id = rand();
		sv->stream_id = rand() % 1024;
		sv->stream_value = rand() % 1024;
		so->optlen = sizeof(struct sctp_stream_value);
		break;
	}

	case SCTP_DEFAULT_PRINFO: {
		struct sctp_default_prinfo *prinfo = (struct sctp_default_prinfo *) so->optval;
		prinfo->pr_assoc_id = rand();
		prinfo->pr_value = rand();
		prinfo->pr_policy = rand() & 0x3;
		so->optlen = sizeof(struct sctp_default_prinfo);
		break;
	}

	case SCTP_EVENT: {
		struct sctp_event *event = (struct sctp_event *) so->optval;
		event->se_assoc_id = rand();
		event->se_type = rand() % 16;
		event->se_on = RAND_BOOL();
		so->optlen = sizeof(struct sctp_event);
		break;
	}

	case SCTP_REMOTE_UDP_ENCAPS_PORT: {
		struct sctp_udpencaps *encaps = (struct sctp_udpencaps *) so->optval;
		memset(encaps, 0, sizeof(*encaps));
		encaps->sue_assoc_id = rand();
		encaps->sue_port = rand() % 65536;
		so->optlen = sizeof(struct sctp_udpencaps);
		break;
	}

	case SCTP_PEER_ADDR_THLDS: {
		struct sctp_paddrthlds *thlds = (struct sctp_paddrthlds *) so->optval;
		memset(thlds, 0, sizeof(*thlds));
		thlds->spt_assoc_id = rand();
		thlds->spt_pathmaxrxt = rand() % 12;
		thlds->spt_pathpfthld = rand() % 12;
		so->optlen = sizeof(struct sctp_paddrthlds);
		break;
	}

	case SCTP_PEER_ADDR_THLDS_V2: {
		struct sctp_paddrthlds_v2 *thlds = (struct sctp_paddrthlds_v2 *) so->optval;
		memset(thlds, 0, sizeof(*thlds));
		thlds->spt_assoc_id = rand();
		thlds->spt_pathmaxrxt = rand() % 12;
		thlds->spt_pathpfthld = rand() % 12;
		thlds->spt_pathcpthld = rand() % 12;
		so->optlen = sizeof(struct sctp_paddrthlds_v2);
		break;
	}

	case SCTP_ADD_STREAMS: {
		struct sctp_add_streams *adds = (struct sctp_add_streams *) so->optval;
		adds->sas_assoc_id = rand();
		adds->sas_instrms = rand() % 16;
		adds->sas_outstrms = rand() % 16;
		so->optlen = sizeof(struct sctp_add_streams);
		break;
	}

	case SCTP_RESET_STREAMS: {
		struct sctp_reset_streams *rstr = (struct sctp_reset_streams *) so->optval;
		unsigned int n = rand() % 4;
		unsigned int i;
		rstr->srs_assoc_id = rand();
		rstr->srs_flags = rand() & 3;
		rstr->srs_number_streams = n;
		for (i = 0; i < n; i++)
			rstr->srs_stream_list[i] = rand() % 16;
		so->optlen = sizeof(struct sctp_reset_streams) + n * sizeof(uint16_t);
		break;
	}

	case SCTP_PLPMTUD_PROBE_INTERVAL: {
		struct sctp_probeinterval *pi = (struct sctp_probeinterval *) so->optval;
		memset(pi, 0, sizeof(*pi));
		pi->spi_assoc_id = rand();
		pi->spi_interval = rand() % 60000;
		so->optlen = sizeof(struct sctp_probeinterval);
		break;
	}

	default:
		break;
	}
}
