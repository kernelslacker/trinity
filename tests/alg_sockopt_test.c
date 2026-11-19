/*
 * Self-check for the AF_ALG option builder: alg_setkey_by_key_serial()
 * (crypto/af_alg.c) takes a key serial four bytes long and looks it up
 * with lookup_user_key(), which finds no key below serial 1 but the
 * special keyrings', so every ALG_SET_KEY_BY_KEY_SERIAL drawn names a
 * serial a key could have.  And an authenc-family transform takes its
 * key as the blob crypto_authenc_extractkeys() parses, so some
 * ALG_SET_KEY draws must be one, with a cipher key AES takes.
 */

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/rtnetlink.h>

#include "debug.h"		/* BUG */
#include "fake_objects.h"	/* fake_get_objhead, fake_no_objhead */
#include "kernel/if_alg.h"	/* ALG_SET_KEY_BY_KEY_SERIAL */
#include "net.h"		/* proto_alg, struct sockopt */
#include "objects.h"		/* struct objhead */

#define ALG_ROUNDS	2000
#define ALG_OPTVAL_LEN	4096

/* crypto_authenc_extractkeys(), with the cipher key held to AES's sizes
 * and an authentication key required. */
static bool authenc_key(const unsigned char *key, unsigned int keylen)
{
	struct rtattr rta;
	uint32_t enckeylen;

	if (keylen < sizeof(rta))
		return false;
	memcpy(&rta, key, sizeof(rta));
	if (!RTA_OK(&rta, keylen) || rta.rta_type != 1 /* KEYA_PARAM */ ||
	    RTA_PAYLOAD(&rta) != sizeof(enckeylen))
		return false;
	memcpy(&enckeylen, key + RTA_LENGTH(0), sizeof(enckeylen));
	enckeylen = ntohl(enckeylen);
	keylen -= rta.rta_len;
	return (enckeylen == 16 || enckeylen == 24 || enckeylen == 32) &&
	       keylen > enckeylen;
}

void alg_sockopt_self_check(void);
void alg_sockopt_self_check(void)
{
	struct socket_triplet alg = {
		.family = PF_ALG, .type = SOCK_SEQPACKET,
	};
	static unsigned char optval[ALG_OPTVAL_LEN];
	unsigned int i, by_serial = 0, authenc = 0;

	/* No key serial pool: the builder draws a serial without one. */
	fake_get_objhead = fake_no_objhead;
	for (i = 0; i < ALG_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		int32_t serial;

		memset(optval, 0, sizeof(optval));
		proto_alg.setsockopt(&so, &alg);
		if (so.optname == ALG_SET_KEY &&
		    authenc_key(optval, so.optlen))
			authenc++;
		if (so.optname != ALG_SET_KEY_BY_KEY_SERIAL)
			continue;

		by_serial++;
		memcpy(&serial, optval, sizeof(serial));
		if (so.optlen != sizeof(serial) || serial < 1)
			BUG("alg: a key-by-serial option names no key");
	}
	fake_get_objhead = NULL;

	if (by_serial == 0)
		BUG("alg: no key-by-serial option drawn");
	if (authenc == 0)
		BUG("alg: no ALG_SET_KEY an authenc transform would take");
}
