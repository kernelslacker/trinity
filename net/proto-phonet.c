#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/phonet.h>
#include <stdlib.h>
#include <string.h>
#include "net.h"
#include "random.h"
#include "compat.h"
#include "rnd.h"

#pragma GCC diagnostic ignored "-Waddress-of-packed-member"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000
#endif

static void phonet_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_pn *pn;

	pn = zmalloc_tracked(sizeof(struct sockaddr_pn));

	pn->spn_family = PF_PHONET;
	pn->spn_obj = rnd_u32();
	pn->spn_dev = rnd_u32();
	pn->spn_resource = rnd_u32();
	*addr = (struct sockaddr *) pn;
	*addrlen = sizeof(struct sockaddr_pn);
}

#define SOL_PNPIPE 275

static void phonet_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	static const unsigned int pnpipe_opts[] = {
		PNPIPE_ENCAP, PNPIPE_IFINDEX, PNPIPE_HANDLE, PNPIPE_INITSTATE,
	};

	so->level = SOL_PNPIPE;
	so->optname = RAND_ARRAY(pnpipe_opts);
	so->optlen = sizeof(unsigned int);
}

/*
 * Fire sendmsg() on a freshly created phonet socket without a prior
 * bind().  Targets the paired pn_socket_autobind / pn_socket_sendmsg
 * BUGs upstream — the autobind path runs from sendmsg on an unbound
 * socket, and the default trinity walk always binds first, so the
 * unbound-sendmsg edge stays cold without an explicit probe here.
 */
static void phonet_socket_setup(int fd)
{
	struct sockaddr_pn dest;
	struct iovec iov;
	struct msghdr msg;
	char buf[16];

	if (!ONE_IN(8))
		return;

	memset(&dest, 0, sizeof(dest));
	dest.spn_family = PF_PHONET;
	dest.spn_obj = rnd_u32();
	dest.spn_dev = rnd_u32();
	dest.spn_resource = rnd_u32();

	memset(buf, 0, sizeof(buf));
	iov.iov_base = buf;
	iov.iov_len  = sizeof(buf);
	memset(&msg, 0, sizeof(msg));
	msg.msg_name    = &dest;
	msg.msg_namelen = sizeof(dest);
	msg.msg_iov     = &iov;
	msg.msg_iovlen  = 1;

	(void) sendmsg(fd, &msg, MSG_NOSIGNAL);
}

static struct socket_triplet phonet_triplets[] = {
	{ .family = PF_PHONET, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_PHONET, .protocol = 0, .type = SOCK_SEQPACKET },
	{ .family = PF_PHONET, .protocol = 1, .type = SOCK_DGRAM },
	{ .family = PF_PHONET, .protocol = 2, .type = SOCK_SEQPACKET },
};

const struct netproto proto_phonet = {
	.name = "phonet",
	.socket_setup = phonet_socket_setup,
	.setsockopt = phonet_setsockopt,
	.gen_sockaddr = phonet_gen_sockaddr,
	.valid_triplets = phonet_triplets,
	.nr_triplets = ARRAY_SIZE(phonet_triplets),
};

#include "socket-family-grammar.h"

const struct socket_family_grammar grammar_phonet_stub = {
	.family		= PF_PHONET,
	.name		= "phonet_stub",
	.can_run	= sfg_always_false,
};
