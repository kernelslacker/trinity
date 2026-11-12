/*
 * Self-check for the NFC option builder: nfc_llcp_setsockopt()
 * (net/nfc/llcp_sock.c) takes NFC_LLCP_RW up to LLCP_MAX_RW (15) and
 * NFC_LLCP_MIUX up to LLCP_MAX_MIUX (0x7ff), and no other option, so
 * the options drawn are ones it takes.
 */

#include <string.h>
#include <sys/socket.h>
#include <linux/nfc.h>

#include "debug.h"		/* BUG */
#include "kernel/nfc.h"		/* NFC_SOCKPROTO_LLCP */
#include "net.h"		/* proto_nfc, struct sockopt */

#define NFC_ROUNDS	2000
#define NFC_OPTVAL_LEN	4096

void nfc_sockopt_self_check(void);
void nfc_sockopt_self_check(void)
{
	struct socket_triplet llcp = {
		.family = PF_NFC, .type = SOCK_STREAM,
		.protocol = NFC_SOCKPROTO_LLCP,
	};
	static unsigned char optval[NFC_OPTVAL_LEN];
	unsigned int i, taken = 0;

	for (i = 0; i < NFC_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		unsigned int val;

		memset(optval, 0, sizeof(optval));
		proto_nfc.setsockopt(&so, &llcp);
		memcpy(&val, optval, sizeof(val));
		if (so.level != SOL_NFC || so.optlen != sizeof(val))
			continue;
		if ((so.optname == NFC_LLCP_RW && val <= 15) ||
		    (so.optname == NFC_LLCP_MIUX && val <= 0x7ff))
			taken++;
	}

	if (taken < NFC_ROUNDS * 3 / 4)
		BUG("nfc: the LLCP options the kernel takes are rare");
}
