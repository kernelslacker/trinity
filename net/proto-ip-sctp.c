#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/sctp.h>
#include "net.h"
#include "random.h"
#include "compat.h"
#include "rnd.h"

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

static void sctp_set_rtoinfo(struct sockopt *so)
{
	struct sctp_rtoinfo *rtoinfo = (struct sctp_rtoinfo *) so->optval;
	rtoinfo->srto_assoc_id = rnd_u32();
	rtoinfo->srto_initial = rnd_modulo_u32(60000);
	rtoinfo->srto_max = rnd_modulo_u32(60000);
	rtoinfo->srto_min = rnd_modulo_u32(60000);
	so->optlen = sizeof(struct sctp_rtoinfo);
}

static void sctp_set_associnfo(struct sockopt *so)
{
	struct sctp_assocparams *assocparams = (struct sctp_assocparams *) so->optval;
	assocparams->sasoc_assoc_id = rnd_u32();
	assocparams->sasoc_asocmaxrxt = rnd_u32();
	assocparams->sasoc_number_peer_destinations = rnd_u32();
	assocparams->sasoc_peer_rwnd = rnd_u32();
	assocparams->sasoc_local_rwnd = rnd_u32();
	assocparams->sasoc_cookie_life = rnd_u32();
	so->optlen = sizeof(struct sctp_assocparams);
}

static void sctp_set_initmsg(struct sockopt *so)
{
	struct sctp_initmsg *initmsg = (struct sctp_initmsg *) so->optval;
	initmsg->sinit_num_ostreams = rnd_u32();
	initmsg->sinit_max_instreams = rnd_u32();
	initmsg->sinit_max_attempts = rnd_u32();
	initmsg->sinit_max_init_timeo = rnd_u32();
	so->optlen = sizeof(struct sctp_initmsg);
}

static void sctp_set_u32_bool(struct sockopt *so)
{
	__u32 *optval32 = (__u32 *) so->optval;
	*optval32 = RAND_BOOL();
	so->optlen = sizeof(__u32);
}

static void sctp_set_autoclose(struct sockopt *so)
{
	__u32 *optval32 = (__u32 *) so->optval;
	*optval32 = rnd_modulo_u32(3600);
	so->optlen = sizeof(__u32);
}

static void sctp_set_fragment_interleave(struct sockopt *so)
{
	__u32 *optval32 = (__u32 *) so->optval;
	*optval32 = rnd_modulo_u32(3);
	so->optlen = sizeof(__u32);
}

static void sctp_set_partial_delivery_point(struct sockopt *so)
{
	__u32 *optval32 = (__u32 *) so->optval;
	*optval32 = 1024 * (1 + rnd_modulo_u32(128));
	so->optlen = sizeof(__u32);
}

static void sctp_set_adaptation_layer(struct sockopt *so)
{
	struct sctp_setadaptation *adapt = (struct sctp_setadaptation *) so->optval;
	adapt->ssb_adaptation_ind = rnd_u32();
	so->optlen = sizeof(struct sctp_setadaptation);
}

static void sctp_set_peer_primary_addr(struct sockopt *so)
{
	struct sctp_setpeerprim *pp = (struct sctp_setpeerprim *) so->optval;
	memset(pp, 0, sizeof(*pp));
	pp->sspp_assoc_id = rnd_u32();
	so->optlen = sizeof(struct sctp_setpeerprim);
}

static void sctp_set_primary_addr(struct sockopt *so)
{
	struct sctp_prim *prim = (struct sctp_prim *) so->optval;
	memset(prim, 0, sizeof(*prim));
	prim->ssp_assoc_id = rnd_u32();
	so->optlen = sizeof(struct sctp_prim);
}

static void sctp_set_default_send_param(struct sockopt *so)
{
	struct sctp_sndrcvinfo *sinfo = (struct sctp_sndrcvinfo *) so->optval;
	sinfo->sinfo_stream = rnd_modulo_u32(65535);
	sinfo->sinfo_ssn = 0;
	sinfo->sinfo_flags = rnd_u32() & 0x010f;
	sinfo->sinfo_ppid = rnd_u32();
	sinfo->sinfo_context = rnd_u32();
	sinfo->sinfo_timetolive = rnd_modulo_u32(60000);
	sinfo->sinfo_tsn = 0;
	sinfo->sinfo_cumtsn = 0;
	sinfo->sinfo_assoc_id = rnd_u32();
	so->optlen = sizeof(struct sctp_sndrcvinfo);
}

static void sctp_set_default_sndinfo(struct sockopt *so)
{
	struct sctp_sndinfo *sndinfo = (struct sctp_sndinfo *) so->optval;
	sndinfo->snd_sid = rnd_modulo_u32(65535);
	sndinfo->snd_flags = rnd_u32() & 0x010f;
	sndinfo->snd_ppid = rnd_u32();
	sndinfo->snd_context = rnd_u32();
	sndinfo->snd_assoc_id = rnd_u32();
	so->optlen = sizeof(struct sctp_sndinfo);
}

static void sctp_set_events(struct sockopt *so)
{
	generate_rand_bytes((unsigned char *) so->optval, sizeof(struct sctp_event_subscribe));
	so->optlen = sizeof(struct sctp_event_subscribe);
}

static void sctp_set_peer_addr_params(struct sockopt *so)
{
	struct sctp_paddrparams *pp = (struct sctp_paddrparams *) so->optval;
	memset(pp, 0, sizeof(*pp));
	pp->spp_assoc_id = rnd_u32();
	pp->spp_hbinterval = rnd_modulo_u32(30000);
	pp->spp_pathmaxrxt = rnd_modulo_u32(12);
	pp->spp_pathmtu = rnd_modulo_u32(65536);
	pp->spp_sackdelay = rnd_modulo_u32(500);
	pp->spp_flags = rnd_u32() & (SPP_HB_ENABLE | SPP_PMTUD_ENABLE | SPP_SACKDELAY_ENABLE);
	so->optlen = sizeof(struct sctp_paddrparams);
}

static void sctp_set_auth_chunk(struct sockopt *so)
{
	struct sctp_authchunk *authchunk = (struct sctp_authchunk *) so->optval;
	authchunk->sauth_chunk = rnd_u32() & 0xff;
	so->optlen = sizeof(struct sctp_authchunk);
}

static void sctp_set_hmac_ident(struct sockopt *so)
{
	static const __u16 hmac_ids[] = { SCTP_AUTH_HMAC_ID_SHA1, SCTP_AUTH_HMAC_ID_SHA256 };
	struct sctp_hmacalgo *hmac = (struct sctp_hmacalgo *) so->optval;
	unsigned int n = 1 + (rnd_modulo_u32(4));
	unsigned int i;
	hmac->shmac_num_idents = n;
	for (i = 0; i < n; i++)
		hmac->shmac_idents[i] = hmac_ids[rnd_modulo_u32(2)];
	so->optlen = sizeof(struct sctp_hmacalgo) + n * sizeof(__u16);
}

static void sctp_set_auth_key(struct sockopt *so)
{
	struct sctp_authkey *authkey = (struct sctp_authkey *) so->optval;
	unsigned int keylen = rnd_modulo_u32(64);
	authkey->sca_assoc_id = rnd_u32();
	authkey->sca_keynumber = rnd_modulo_u32(8);
	authkey->sca_keylength = keylen;
	generate_rand_bytes(authkey->sca_key, keylen);
	so->optlen = sizeof(struct sctp_authkey) + keylen;
}

static void sctp_set_authkeyid(struct sockopt *so)
{
	struct sctp_authkeyid *keyid = (struct sctp_authkeyid *) so->optval;
	keyid->scact_assoc_id = rnd_u32();
	keyid->scact_keynumber = rnd_modulo_u32(8);
	so->optlen = sizeof(struct sctp_authkeyid);
}

static void sctp_set_delayed_ack_time(struct sockopt *so)
{
	struct sctp_sack_info *sack = (struct sctp_sack_info *) so->optval;
	sack->sack_assoc_id = rnd_u32();
	sack->sack_delay = rnd_modulo_u32(500);
	sack->sack_freq = 1 + (rnd_modulo_u32(8));
	so->optlen = sizeof(struct sctp_sack_info);
}

static void sctp_set_assoc_value(struct sockopt *so)
{
	struct sctp_assoc_value *av = (struct sctp_assoc_value *) so->optval;
	av->assoc_id = rnd_u32();
	av->assoc_value = rnd_u32();
	so->optlen = sizeof(struct sctp_assoc_value);
}

static void sctp_set_stream_scheduler(struct sockopt *so)
{
	struct sctp_assoc_value *av = (struct sctp_assoc_value *) so->optval;
	av->assoc_id = rnd_u32();
	av->assoc_value = rnd_modulo_u32(SCTP_SS_MAX + 1);
	so->optlen = sizeof(struct sctp_assoc_value);
}

static void sctp_set_stream_scheduler_value(struct sockopt *so)
{
	struct sctp_stream_value *sv = (struct sctp_stream_value *) so->optval;
	sv->assoc_id = rnd_u32();
	sv->stream_id = rnd_modulo_u32(1024);
	sv->stream_value = rnd_modulo_u32(1024);
	so->optlen = sizeof(struct sctp_stream_value);
}

static void sctp_set_default_prinfo(struct sockopt *so)
{
	struct sctp_default_prinfo *prinfo = (struct sctp_default_prinfo *) so->optval;
	prinfo->pr_assoc_id = rnd_u32();
	prinfo->pr_value = rnd_u32();
	prinfo->pr_policy = rnd_u32() & 0x3;
	so->optlen = sizeof(struct sctp_default_prinfo);
}

static void sctp_set_event(struct sockopt *so)
{
	struct sctp_event *event = (struct sctp_event *) so->optval;
	event->se_assoc_id = rnd_u32();
	event->se_type = rnd_modulo_u32(16);
	event->se_on = RAND_BOOL();
	so->optlen = sizeof(struct sctp_event);
}

static void sctp_set_remote_udp_encaps_port(struct sockopt *so)
{
	struct sctp_udpencaps *encaps = (struct sctp_udpencaps *) so->optval;
	memset(encaps, 0, sizeof(*encaps));
	encaps->sue_assoc_id = rnd_u32();
	encaps->sue_port = rnd_modulo_u32(65536);
	so->optlen = sizeof(struct sctp_udpencaps);
}

static void sctp_set_peer_addr_thlds(struct sockopt *so)
{
	struct sctp_paddrthlds *thlds = (struct sctp_paddrthlds *) so->optval;
	memset(thlds, 0, sizeof(*thlds));
	thlds->spt_assoc_id = rnd_u32();
	thlds->spt_pathmaxrxt = rnd_modulo_u32(12);
	thlds->spt_pathpfthld = rnd_modulo_u32(12);
	so->optlen = sizeof(struct sctp_paddrthlds);
}

static void sctp_set_peer_addr_thlds_v2(struct sockopt *so)
{
	struct sctp_paddrthlds_v2 *thlds = (struct sctp_paddrthlds_v2 *) so->optval;
	memset(thlds, 0, sizeof(*thlds));
	thlds->spt_assoc_id = rnd_u32();
	thlds->spt_pathmaxrxt = rnd_modulo_u32(12);
	thlds->spt_pathpfthld = rnd_modulo_u32(12);
	thlds->spt_pathcpthld = rnd_modulo_u32(12);
	so->optlen = sizeof(struct sctp_paddrthlds_v2);
}

static void sctp_set_add_streams(struct sockopt *so)
{
	struct sctp_add_streams *adds = (struct sctp_add_streams *) so->optval;
	adds->sas_assoc_id = rnd_u32();
	adds->sas_instrms = rnd_modulo_u32(16);
	adds->sas_outstrms = rnd_modulo_u32(16);
	so->optlen = sizeof(struct sctp_add_streams);
}

static void sctp_set_reset_streams(struct sockopt *so)
{
	struct sctp_reset_streams *rstr = (struct sctp_reset_streams *) so->optval;
	unsigned int n = rnd_modulo_u32(4);
	unsigned int i;
	rstr->srs_assoc_id = rnd_u32();
	rstr->srs_flags = rnd_u32() & 3;
	rstr->srs_number_streams = n;
	for (i = 0; i < n; i++)
		rstr->srs_stream_list[i] = rnd_modulo_u32(16);
	so->optlen = sizeof(struct sctp_reset_streams) + n * sizeof(uint16_t);
}

static void sctp_set_bindx(struct sockopt *so)
{
	/* Kernel reads an inline array of sockaddr entries; optlen is
	 * the total byte count of that array. See net/sctp/socket.c
	 * sctp_setsockopt_bindx / __sctp_setsockopt_connectx.
	 */
	struct sockaddr_in *sa = (struct sockaddr_in *) so->optval;
	unsigned int n = 1 + rnd_modulo_u32(4);
	unsigned int i;
	memset(sa, 0, n * sizeof(*sa));
	for (i = 0; i < n; i++) {
		sa[i].sin_family = AF_INET;
		sa[i].sin_port = htons(rnd_modulo_u32(65535) + 1);
		sa[i].sin_addr.s_addr = htonl(0x7f000000 | rnd_modulo_u32(256));
	}
	so->optlen = n * sizeof(struct sockaddr_in);
}

static void sctp_set_connectx3(struct sockopt *so)
{
	/* See net/sctp/socket.c sctp_setsockopt_connectx3: kernel
	 * expects optlen >= sizeof(struct sctp_getaddrs_old) and reads
	 * the addrs array from the user pointer inside the struct.
	 */
	struct sctp_getaddrs_old *gao = (struct sctp_getaddrs_old *) so->optval;
	struct sockaddr_in *sa = (struct sockaddr_in *) (gao + 1);
	unsigned int n = 1 + rnd_modulo_u32(4);
	unsigned int i;
	memset(sa, 0, n * sizeof(*sa));
	for (i = 0; i < n; i++) {
		sa[i].sin_family = AF_INET;
		sa[i].sin_port = htons(rnd_modulo_u32(65535) + 1);
		sa[i].sin_addr.s_addr = htonl(0x7f000000 | rnd_modulo_u32(256));
	}
	gao->assoc_id = rnd_u32();
	gao->addr_num = n;
	gao->addrs = (struct sockaddr *) sa;
	so->optlen = sizeof(struct sctp_getaddrs_old);
}

static void sctp_set_peeloff(struct sockopt *so)
{
	sctp_peeloff_arg_t *arg = (sctp_peeloff_arg_t *) so->optval;
	arg->associd = rnd_u32();
	arg->sd = rnd_u32();
	so->optlen = sizeof(sctp_peeloff_arg_t);
}

static void sctp_set_peeloff_flags(struct sockopt *so)
{
	sctp_peeloff_flags_arg_t *arg = (sctp_peeloff_flags_arg_t *) so->optval;
	arg->p_arg.associd = rnd_u32();
	arg->p_arg.sd = rnd_u32();
	arg->flags = rnd_u32();
	so->optlen = sizeof(sctp_peeloff_flags_arg_t);
}

static void sctp_set_plpmtud_probe_interval(struct sockopt *so)
{
	struct sctp_probeinterval *pi = (struct sctp_probeinterval *) so->optval;
	memset(pi, 0, sizeof(*pi));
	pi->spi_assoc_id = rnd_u32();
	pi->spi_interval = rnd_modulo_u32(60000);
	so->optlen = sizeof(struct sctp_probeinterval);
}

void sctp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->optname = RAND_ARRAY(sctp_opts);

	switch (so->optname) {
	case SCTP_RTOINFO:
		sctp_set_rtoinfo(so);
		break;

	case SCTP_ASSOCINFO:
		sctp_set_associnfo(so);
		break;

	case SCTP_INITMSG:
		sctp_set_initmsg(so);
		break;

	case SCTP_NODELAY:
	case SCTP_DISABLE_FRAGMENTS:
	case SCTP_I_WANT_MAPPED_V4_ADDR:
	case SCTP_AUTO_ASCONF:
	case SCTP_REUSE_PORT:
		sctp_set_u32_bool(so);
		break;

	case SCTP_AUTOCLOSE:
		sctp_set_autoclose(so);
		break;

	case SCTP_FRAGMENT_INTERLEAVE:
		sctp_set_fragment_interleave(so);
		break;

	case SCTP_PARTIAL_DELIVERY_POINT:
		sctp_set_partial_delivery_point(so);
		break;

	case SCTP_ADAPTATION_LAYER:
		sctp_set_adaptation_layer(so);
		break;

	case SCTP_SET_PEER_PRIMARY_ADDR:
		sctp_set_peer_primary_addr(so);
		break;

	case SCTP_PRIMARY_ADDR:
		sctp_set_primary_addr(so);
		break;

	case SCTP_DEFAULT_SEND_PARAM:
		sctp_set_default_send_param(so);
		break;

	case SCTP_DEFAULT_SNDINFO:
		sctp_set_default_sndinfo(so);
		break;

	case SCTP_EVENTS:
		sctp_set_events(so);
		break;

	case SCTP_PEER_ADDR_PARAMS:
		sctp_set_peer_addr_params(so);
		break;

	case SCTP_AUTH_CHUNK:
		sctp_set_auth_chunk(so);
		break;

	case SCTP_HMAC_IDENT:
		sctp_set_hmac_ident(so);
		break;

	case SCTP_AUTH_KEY:
		sctp_set_auth_key(so);
		break;

	case SCTP_AUTH_ACTIVE_KEY:
	case SCTP_AUTH_DELETE_KEY:
	case SCTP_AUTH_DEACTIVATE_KEY:
		sctp_set_authkeyid(so);
		break;

	case SCTP_DELAYED_ACK_TIME:
		sctp_set_delayed_ack_time(so);
		break;

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
		sctp_set_assoc_value(so);
		break;

	case SCTP_STREAM_SCHEDULER:
		sctp_set_stream_scheduler(so);
		break;

	case SCTP_STREAM_SCHEDULER_VALUE:
		sctp_set_stream_scheduler_value(so);
		break;

	case SCTP_DEFAULT_PRINFO:
		sctp_set_default_prinfo(so);
		break;

	case SCTP_EVENT:
		sctp_set_event(so);
		break;

	case SCTP_REMOTE_UDP_ENCAPS_PORT:
		sctp_set_remote_udp_encaps_port(so);
		break;

	case SCTP_PEER_ADDR_THLDS:
		sctp_set_peer_addr_thlds(so);
		break;

	case SCTP_PEER_ADDR_THLDS_V2:
		sctp_set_peer_addr_thlds_v2(so);
		break;

	case SCTP_ADD_STREAMS:
		sctp_set_add_streams(so);
		break;

	case SCTP_RESET_STREAMS:
		sctp_set_reset_streams(so);
		break;

	case SCTP_SOCKOPT_BINDX_ADD:
	case SCTP_SOCKOPT_BINDX_REM:
	case SCTP_SOCKOPT_CONNECTX:
	case SCTP_SOCKOPT_CONNECTX_OLD:
		sctp_set_bindx(so);
		break;

	case SCTP_SOCKOPT_CONNECTX3:
		sctp_set_connectx3(so);
		break;

	case SCTP_SOCKOPT_PEELOFF:
		sctp_set_peeloff(so);
		break;

	case SCTP_SOCKOPT_PEELOFF_FLAGS:
		sctp_set_peeloff_flags(so);
		break;

	case SCTP_PLPMTUD_PROBE_INTERVAL:
		sctp_set_plpmtud_probe_interval(so);
		break;

	default:
		so->optlen = sizeof(int);
		break;
	}
}
