#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/nfc.h>
#include <stdlib.h>
#include "compat.h"
#include "net.h"
#include "random.h"

static void nfc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	if (RAND_BOOL()) {
		struct sockaddr_nfc_llcp *nfc_llcp;
		unsigned int i;

		nfc_llcp = zmalloc(sizeof(struct sockaddr_nfc_llcp));

		nfc_llcp->sa_family = PF_NFC;
		nfc_llcp->dev_idx = rand();
		nfc_llcp->target_idx = rand();
		nfc_llcp->nfc_protocol = rand() % 5;
		nfc_llcp->dsap = rand();
		nfc_llcp->ssap = rand();
		nfc_llcp->service_name_len = rand() % NFC_LLCP_MAX_SERVICE_NAME;
		for (i = 0; i < nfc_llcp->service_name_len; i++)
			nfc_llcp->service_name[i] = 'a' + rand() % 26;
		*addr = (struct sockaddr *) nfc_llcp;
		*addrlen = sizeof(struct sockaddr_nfc_llcp);
	} else {
		struct sockaddr_nfc *nfc;

		nfc = zmalloc(sizeof(struct sockaddr_nfc));

		nfc->sa_family = PF_NFC;
		nfc->dev_idx = rand();
		nfc->target_idx = rand();
		nfc->nfc_protocol = rand() % 5;
		*addr = (struct sockaddr *) nfc;
		*addrlen = sizeof(struct sockaddr_nfc);
	}
}

static const unsigned int nfc_opts[] = {
	NFC_LLCP_RW, NFC_LLCP_MIUX,
	NFC_LLCP_REMOTE_MIU, NFC_LLCP_REMOTE_LTO, NFC_LLCP_REMOTE_RW,
};

static void nfc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned int *optval32;

	so->level = SOL_NFC;
	so->optname = RAND_ARRAY(nfc_opts);

	optval32 = (unsigned int *) so->optval;
	*optval32 = rand();
	so->optlen = sizeof(unsigned int);
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
