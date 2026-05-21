#include <stdlib.h>
#include <string.h>
#include <linux/tcp.h>
#include "net.h"
#include "random.h"
#include "compat.h"
#include "rnd.h"

static const unsigned int tcp_opts[] = {
	TCP_NODELAY, TCP_MAXSEG, TCP_CORK, TCP_KEEPIDLE,
	TCP_KEEPINTVL, TCP_KEEPCNT, TCP_SYNCNT, TCP_LINGER2,
	TCP_DEFER_ACCEPT, TCP_WINDOW_CLAMP, TCP_INFO, TCP_QUICKACK,
	TCP_CONGESTION, TCP_MD5SIG, TCP_THIN_LINEAR_TIMEOUTS,
	TCP_THIN_DUPACK, TCP_USER_TIMEOUT, TCP_REPAIR, TCP_REPAIR_QUEUE,
	TCP_QUEUE_SEQ, TCP_REPAIR_OPTIONS, TCP_FASTOPEN, TCP_TIMESTAMP,
	TCP_NOTSENT_LOWAT, TCP_CC_INFO, TCP_SAVE_SYN, TCP_SAVED_SYN,
	TCP_REPAIR_WINDOW, TCP_FASTOPEN_CONNECT, TCP_ULP, TCP_MD5SIG_EXT,
	TCP_FASTOPEN_KEY, TCP_FASTOPEN_NO_COOKIE, TCP_ZEROCOPY_RECEIVE, TCP_INQ,
	TCP_TX_DELAY,
	TCP_AO_ADD_KEY, TCP_AO_DEL_KEY, TCP_AO_INFO, TCP_AO_GET_KEYS, TCP_AO_REPAIR,
	TCP_IS_MPTCP, TCP_RTO_MAX_MS, TCP_RTO_MIN_US, TCP_DELACK_MAX_US,
};

static const char *ulp_names[] = { "tls", "mptcp" };

static const char *cc_algos[] = { "cubic", "reno", "bbr", "dctcp", "vegas", "westwood" };

static const char *ao_algos[] = { "hmac(sha1)", "cmac(aes)", "hmac(sha256)" };

void tcp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	char *ptr;
	const char *str;

	so->optname = RAND_ARRAY(tcp_opts);

	switch (so->optname) {
	case TCP_ULP:
		ptr = (char *) so->optval;
		str = RAND_ARRAY(ulp_names);
		so->optlen = strlen(str) + 1;
		memcpy(ptr, str, so->optlen);
		break;

	case TCP_CONGESTION:
		ptr = (char *) so->optval;
		str = RAND_ARRAY(cc_algos);
		so->optlen = strlen(str) + 1;
		memcpy(ptr, str, so->optlen);
		break;

	case TCP_MD5SIG:
	case TCP_MD5SIG_EXT: {
		struct tcp_md5sig *md5 = (struct tcp_md5sig *) so->optval;

		memset(md5, 0, sizeof(struct tcp_md5sig));
		md5->tcpm_keylen = rnd_modulo_u32(TCP_MD5SIG_MAXKEYLEN + 1);
		generate_rand_bytes(md5->tcpm_key, md5->tcpm_keylen);
		if (so->optname == TCP_MD5SIG_EXT) {
			md5->tcpm_flags = rnd_u32() & 0x3;
			md5->tcpm_prefixlen = rnd_modulo_u32(129);
		}
		so->optlen = sizeof(struct tcp_md5sig);
		break;
	}

	case TCP_FASTOPEN_KEY:
		/* Key is 16 bytes (AES-128), kernel accepts 1 or 2 keys */
		switch (rnd_modulo_u32(3)) {
		case 0: so->optlen = 16; break;
		case 1: so->optlen = 32; break;
		case 2: so->optlen = rnd_modulo_u32(48) + 1; break;
		}
		generate_rand_bytes((unsigned char *) so->optval, so->optlen);
		break;

	case TCP_REPAIR_OPTIONS: {
		struct tcp_repair_opt *opt = (struct tcp_repair_opt *) so->optval;
		unsigned int count = rnd_modulo_u32(4) + 1;
		unsigned int i;

		for (i = 0; i < count; i++) {
			opt[i].opt_code = rnd_modulo_u32(16);
			opt[i].opt_val = rnd_u32();
		}
		so->optlen = count * sizeof(struct tcp_repair_opt);
		break;
	}

	case TCP_AO_ADD_KEY: {
		struct tcp_ao_add *ao = (struct tcp_ao_add *) so->optval;

		memset(ao, 0, sizeof(struct tcp_ao_add));
		str = RAND_ARRAY(ao_algos);
		strncpy(ao->alg_name, str, sizeof(ao->alg_name) - 1);
		ao->sndid = rnd_u32();
		ao->rcvid = rnd_u32();
		ao->keylen = rnd_modulo_u32(TCP_AO_MAXKEYLEN + 1);
		generate_rand_bytes(ao->key, ao->keylen);
		ao->maclen = rnd_modulo_u32(2) ? 12 : 16;
		ao->keyflags = rnd_u32() & 0x3;
		ao->set_current = rnd_u32() & 1;
		ao->set_rnext = rnd_u32() & 1;
		ao->prefix = rnd_modulo_u32(129);
		ao->ifindex = rnd_modulo_u32(4);
		so->optlen = sizeof(struct tcp_ao_add);
		break;
	}

	case TCP_AO_DEL_KEY: {
		struct tcp_ao_del *del = (struct tcp_ao_del *) so->optval;

		memset(del, 0, sizeof(struct tcp_ao_del));
		del->sndid = rnd_u32();
		del->rcvid = rnd_u32();
		del->set_current = rnd_u32() & 1;
		del->set_rnext = rnd_u32() & 1;
		del->del_async = rnd_u32() & 1;
		del->current_key = rnd_u32();
		del->rnext = rnd_u32();
		del->prefix = rnd_modulo_u32(129);
		del->keyflags = rnd_u32() & 0x3;
		del->ifindex = rnd_modulo_u32(4);
		so->optlen = sizeof(struct tcp_ao_del);
		break;
	}

	case TCP_AO_INFO: {
		struct tcp_ao_info_opt *info = (struct tcp_ao_info_opt *) so->optval;

		memset(info, 0, sizeof(struct tcp_ao_info_opt));
		info->set_current = rnd_u32() & 1;
		info->set_rnext = rnd_u32() & 1;
		info->ao_required = rnd_u32() & 1;
		info->set_counters = rnd_u32() & 1;
		info->accept_icmps = rnd_u32() & 1;
		info->current_key = rnd_u32();
		info->rnext = rnd_u32();
		so->optlen = sizeof(struct tcp_ao_info_opt);
		break;
	}

	case TCP_AO_REPAIR: {
		struct tcp_ao_repair *repair = (struct tcp_ao_repair *) so->optval;

		repair->snt_isn = rnd_u32();
		repair->rcv_isn = rnd_u32();
		repair->snd_sne = rnd_u32();
		repair->rcv_sne = rnd_u32();
		so->optlen = sizeof(struct tcp_ao_repair);
		break;
	}

	default:
		break;
	}
}
