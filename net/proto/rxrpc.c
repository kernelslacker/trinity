#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include "net.h"
#include "pids.h"
#include "random.h"
#include "utils.h"
#include "kernel/rxrpc.h"
#include "rnd.h"

#include "kernel/socket.h"
static const unsigned int rxrpc_opts[] = {
	RXRPC_SECURITY_KEY,
	RXRPC_SECURITY_KEYRING,
	RXRPC_EXCLUSIVE_CONNECTION,
	RXRPC_MIN_SECURITY_LEVEL,
	RXRPC_UPGRADEABLE_SERVICE,
	RXRPC_MANAGE_RESPONSE,
};

static void rxrpc_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_rxrpc *rxrpc;

	rxrpc = zmalloc_tracked(sizeof(struct sockaddr_rxrpc));
	rxrpc->srx_family = AF_RXRPC;
	rxrpc->srx_service = rnd_u32();
	rxrpc->transport_type = SOCK_DGRAM;

	if (RAND_BOOL()) {
		rxrpc->transport_len = sizeof(struct sockaddr_in);
		rxrpc->transport.sin.sin_family = AF_INET;
		rxrpc->transport.sin.sin_addr.s_addr = random_ipv4_address();
		rxrpc->transport.sin.sin_port = htons(rnd_modulo_u32(65536));
	} else {
		rxrpc->transport_len = sizeof(struct sockaddr_in6);
		rxrpc->transport.sin6.sin6_family = AF_INET6;
		rxrpc->transport.sin6.sin6_addr.s6_addr32[3] = htonl(1); /* ::1 */
		rxrpc->transport.sin6.sin6_port = htons(rnd_modulo_u32(65536));
	}

	*addr = (struct sockaddr *) rxrpc;
	*addrlen = sizeof(struct sockaddr_rxrpc);
}

/*
 * A description for RXRPC_SECURITY_KEY, which request_key()s an rxrpc key
 * of that name from the caller's keyrings, or for RXRPC_SECURITY_KEYRING,
 * which request_key()s a keyring.  Neither passes callout info, so a miss
 * is -ENOKEY without an upcall.  Most keys are named as rxrpc_key_install
 * names the ones it adds to this child's thread keyring, by kind, pid and
 * an iteration below its cap of 48 (childops/net/rxrpc-key-install.c),
 * and most keyrings as the user's own.
 */
static void rxrpc_key_description(struct sockopt *so)
{
	static const char *const kinds[] = {
		"null", "short", "v1", "xdr", "xrxkad", "xrxgk",
	};
	char *desc = (char *) so->optval;
	int len;

	if (ONE_IN(4))
		len = snprintf(desc, 64, "trinity-rxrpc-%u", rnd_u32());
	else if (so->optname == RXRPC_SECURITY_KEYRING)
		len = snprintf(desc, 64, "_uid.%u", (unsigned int) getuid());
	else
		len = snprintf(desc, 64, "trinity-rxrpc-%s-%u-%u",
			       RAND_ARRAY(kinds), (unsigned int) mypid(),
			       rnd_modulo_u32(48));
	so->optlen = len;
}

static void rxrpc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned short *optval_us;
	unsigned int *optval32;

	so->level = SOL_RXRPC;
	so->optname = RAND_ARRAY(rxrpc_opts);

	switch (so->optname) {
	case RXRPC_SECURITY_KEY:
	case RXRPC_SECURITY_KEYRING:
		rxrpc_key_description(so);
		break;
	case RXRPC_EXCLUSIVE_CONNECTION:
		/* Taken only at an optlen of 0, on an unbound socket. */
		so->optlen = 0;
		break;
	case RXRPC_MIN_SECURITY_LEVEL:
		/* 0=plain, 1=auth, 2=encrypt */
		optval32 = (unsigned int *) so->optval;
		*optval32 = rnd_modulo_u32(3);
		so->optlen = sizeof(unsigned int);
		break;
	case RXRPC_UPGRADEABLE_SERVICE:
		/* two unsigned short values: service[0] -> service[1] */
		optval_us = (unsigned short *) so->optval;
		optval_us[0] = rnd_u32();
		optval_us[1] = rnd_u32();
		so->optlen = 2 * sizeof(unsigned short);
		break;
	case RXRPC_MANAGE_RESPONSE:
		/* rxrpc_setsockopt() takes 0 or 1. */
		optval32 = (unsigned int *) so->optval;
		*optval32 = RAND_BOOL();
		so->optlen = sizeof(unsigned int);
		break;
	}
}

static struct socket_triplet rxrpc_triplet[] = {
	{ .family = PF_RXRPC, .protocol = PF_INET, .type = SOCK_DGRAM },
	{ .family = PF_RXRPC, .protocol = PF_INET6, .type = SOCK_DGRAM },
};

const struct netproto proto_rxrpc = {
	.name = "rxrpc",
	.gen_sockaddr = rxrpc_gen_sockaddr,
	.setsockopt = rxrpc_setsockopt,
	.valid_triplets = rxrpc_triplet,
	.nr_triplets = ARRAY_SIZE(rxrpc_triplet),
};
