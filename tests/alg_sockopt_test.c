/*
 * Self-check for the AF_ALG option builder: alg_setkey_by_key_serial()
 * (crypto/af_alg.c) takes a key serial four bytes long and looks it up
 * with lookup_user_key(), which finds no key below serial 1 but the
 * special keyrings', so every ALG_SET_KEY_BY_KEY_SERIAL drawn names a
 * serial a key could have.
 */

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include "debug.h"		/* BUG */
#include "fake_objects.h"	/* fake_get_objhead, fake_no_objhead */
#include "kernel/if_alg.h"	/* ALG_SET_KEY_BY_KEY_SERIAL */
#include "net.h"		/* proto_alg, struct sockopt */
#include "objects.h"		/* struct objhead */

#define ALG_ROUNDS	2000
#define ALG_OPTVAL_LEN	4096

void alg_sockopt_self_check(void);
void alg_sockopt_self_check(void)
{
	struct socket_triplet alg = {
		.family = PF_ALG, .type = SOCK_SEQPACKET,
	};
	static unsigned char optval[ALG_OPTVAL_LEN];
	unsigned int i, by_serial = 0;

	/* No key serial pool: the builder draws a serial without one. */
	fake_get_objhead = fake_no_objhead;
	for (i = 0; i < ALG_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		int32_t serial;

		memset(optval, 0, sizeof(optval));
		proto_alg.setsockopt(&so, &alg);
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
}
