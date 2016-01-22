#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "config.h"
#include "compat.h"
#include "net.h"
#include "random.h"
#include "utils.h"

void nfc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_nfc *nfc;

	// TODO: See also sockaddr_nfc_llcp
	nfc = zmalloc(sizeof(struct sockaddr_nfc));

	nfc->sa_family = PF_NFC;
	nfc->dev_idx = rnd();
	nfc->target_idx = rnd();
	nfc->nfc_protocol = rnd() % 5;
	*addr = (struct sockaddr *) nfc;
	*addrlen = sizeof(struct sockaddr_nfc);
}

static void nfc_rand_socket(struct socket_triplet *st)
{
	if (RAND_BOOL()) {
		st->protocol = NFC_SOCKPROTO_LLCP;
		if (RAND_BOOL())
			st->type = SOCK_DGRAM;
		else
			st->type = SOCK_STREAM;
		return;
	}

	st->protocol = NFC_SOCKPROTO_RAW;
	st->type = SOCK_SEQPACKET;
}

static void nfc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_NFC;
}

struct netproto proto_nfc = {
	.name = "nfc",
	.socket = nfc_rand_socket,
	.setsockopt = nfc_setsockopt,
};
