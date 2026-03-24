#include <stdlib.h>
#include <string.h>
#include <linux/tcp.h>
#include "net.h"
#include "random.h"
#include "compat.h"

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
		md5->tcpm_keylen = rand() % (TCP_MD5SIG_MAXKEYLEN + 1);
		generate_rand_bytes(md5->tcpm_key, md5->tcpm_keylen);
		if (so->optname == TCP_MD5SIG_EXT) {
			md5->tcpm_flags = rand() & 0x3;
			md5->tcpm_prefixlen = rand() % 129;
		}
		so->optlen = sizeof(struct tcp_md5sig);
		break;
	}

	case TCP_FASTOPEN_KEY:
		/* Key is 16 bytes (AES-128), kernel accepts 1 or 2 keys */
		switch (rand() % 3) {
		case 0: so->optlen = 16; break;
		case 1: so->optlen = 32; break;
		case 2: so->optlen = rand() % 48 + 1; break;
		}
		generate_rand_bytes((unsigned char *) so->optval, so->optlen);
		break;

	case TCP_REPAIR_OPTIONS: {
		struct tcp_repair_opt *opt = (struct tcp_repair_opt *) so->optval;
		unsigned int count = rand() % 4 + 1;
		unsigned int i;

		for (i = 0; i < count; i++) {
			opt[i].opt_code = rand() % 16;
			opt[i].opt_val = rand();
		}
		so->optlen = count * sizeof(struct tcp_repair_opt);
		break;
	}

	case TCP_AO_ADD_KEY: {
		struct tcp_ao_add *ao = (struct tcp_ao_add *) so->optval;

		memset(ao, 0, sizeof(struct tcp_ao_add));
		str = RAND_ARRAY(ao_algos);
		strncpy(ao->alg_name, str, sizeof(ao->alg_name) - 1);
		ao->sndid = rand();
		ao->rcvid = rand();
		ao->keylen = rand() % (TCP_AO_MAXKEYLEN + 1);
		generate_rand_bytes(ao->key, ao->keylen);
		ao->maclen = rand() % 2 ? 12 : 16;
		ao->keyflags = rand() & 0x3;
		ao->set_current = rand() & 1;
		ao->set_rnext = rand() & 1;
		ao->prefix = rand() % 129;
		ao->ifindex = rand() % 4;
		so->optlen = sizeof(struct tcp_ao_add);
		break;
	}

	case TCP_AO_DEL_KEY: {
		struct tcp_ao_del *del = (struct tcp_ao_del *) so->optval;

		memset(del, 0, sizeof(struct tcp_ao_del));
		del->sndid = rand();
		del->rcvid = rand();
		del->set_current = rand() & 1;
		del->set_rnext = rand() & 1;
		del->del_async = rand() & 1;
		del->current_key = rand();
		del->rnext = rand();
		del->prefix = rand() % 129;
		del->keyflags = rand() & 0x3;
		del->ifindex = rand() % 4;
		so->optlen = sizeof(struct tcp_ao_del);
		break;
	}

	case TCP_AO_INFO: {
		struct tcp_ao_info_opt *info = (struct tcp_ao_info_opt *) so->optval;

		memset(info, 0, sizeof(struct tcp_ao_info_opt));
		info->set_current = rand() & 1;
		info->set_rnext = rand() & 1;
		info->ao_required = rand() & 1;
		info->set_counters = rand() & 1;
		info->accept_icmps = rand() & 1;
		info->current_key = rand();
		info->rnext = rand();
		so->optlen = sizeof(struct tcp_ao_info_opt);
		break;
	}

	case TCP_AO_REPAIR: {
		struct tcp_ao_repair *repair = (struct tcp_ao_repair *) so->optval;

		repair->snt_isn = rand();
		repair->rcv_isn = rand();
		repair->snd_sne = rand();
		repair->rcv_sne = rand();
		so->optlen = sizeof(struct tcp_ao_repair);
		break;
	}

	default:
		break;
	}
}
