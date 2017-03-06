#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "compat.h"
#include "net.h"
#include "random.h"
#include "utils.h"

static void nfc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
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

#define SOL_NFC 280

static void nfc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_NFC;
}

static struct socket_triplet nfc_triplets[] = {
	{ .family = PF_NFC, .protocol = NFC_SOCKPROTO_RAW, .type = SOCK_SEQPACKET },
	{ .family = PF_NFC, .protocol = NFC_SOCKPROTO_RAW, .type = SOCK_RAW },

	{ .family = PF_NFC, .protocol = NFC_SOCKPROTO_LLCP, .type = SOCK_DGRAM },
	{ .family = PF_NFC, .protocol = NFC_SOCKPROTO_LLCP, .type = SOCK_STREAM },
	{ .family = PF_NFC, .protocol = NFC_SOCKPROTO_LLCP, .type = SOCK_RAW },
};

const struct netproto proto_nfc = {
	.name = "nfc",
	.setsockopt = nfc_setsockopt,
	.gen_sockaddr = nfc_gen_sockaddr,
	.valid_triplets = nfc_triplets,
	.nr_triplets = ARRAY_SIZE(nfc_triplets),
};
