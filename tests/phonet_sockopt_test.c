/*
 * Self-check for the Phonet pipe option builder: pep_setsockopt()
 * (net/phonet/pep.c) reads an int, takes PNPIPE_ENCAP as NONE or IP,
 * PNPIPE_HANDLE below PN_PIPE_INVALID_HANDLE (0xff) and PNPIPE_INITSTATE
 * as a flag, and has no PNPIPE_IFINDEX, which only getsockopt answers.
 */

#include <string.h>
#include <sys/socket.h>
#include <linux/phonet.h>

#include "debug.h"		/* BUG */
#include "net.h"		/* proto_phonet, struct sockopt */

#define PN_ROUNDS	4000
#define PN_OPTVAL_LEN	4096

void phonet_sockopt_self_check(void);
void phonet_sockopt_self_check(void)
{
	struct socket_triplet pipe = {
		.family = PF_PHONET, .type = SOCK_SEQPACKET, .protocol = 2,
	};
	static unsigned char optval[PN_OPTVAL_LEN];
	unsigned int i, encap_ip = 0, encap_none = 0, on = 0, off = 0;

	for (i = 0; i < PN_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		unsigned int val;

		memset(optval, 0, sizeof(optval));
		proto_phonet.setsockopt(&so, &pipe);
		if (so.optlen < sizeof(int))
			BUG("phonet: an option shorter than the int pep_setsockopt() reads");
		memcpy(&val, optval, sizeof(val));

		switch (so.optname) {
		case PNPIPE_ENCAP:
			if (val == PNPIPE_ENCAP_IP)
				encap_ip++;
			else if (val == PNPIPE_ENCAP_NONE)
				encap_none++;
			else
				BUG("phonet: a PNPIPE_ENCAP pep_setsockopt() refuses");
			break;
		case PNPIPE_HANDLE:
			if (val >= 0xff)
				BUG("phonet: a PNPIPE_HANDLE at or past PN_PIPE_INVALID_HANDLE");
			break;
		case PNPIPE_INITSTATE:
			if (val != 0)
				on++;
			else
				off++;
			break;
		default:
			BUG("phonet: an option pep_setsockopt() does not take");
		}
	}

	if (encap_ip == 0 || encap_none == 0)
		BUG("phonet: PNPIPE_ENCAP never asks for both encapsulations");
	if (on == 0 || off == 0)
		BUG("phonet: PNPIPE_INITSTATE never turns both on and off");
}
