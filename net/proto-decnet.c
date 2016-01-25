#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/dn.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

static void decnet_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_dn *dn;
	unsigned int i;

	dn = zmalloc(sizeof(struct sockaddr_dn));

	dn->sdn_family = PF_DECnet;
	dn->sdn_flags = rnd();
	dn->sdn_objnum = rnd();
	dn->sdn_objnamel = rnd() % 16;
	for (i = 0; i < dn->sdn_objnamel; i++)
		dn->sdn_objname[i] = rnd();
	dn->sdn_add.a_len = RAND_BOOL();
	dn->sdn_add.a_addr[0] = rnd();
	dn->sdn_add.a_addr[1] = rnd();
	*addr = (struct sockaddr *) dn;
	*addrlen = sizeof(struct sockaddr_dn);
}

static void decnet_rand_socket(struct socket_triplet *st)
{
	if (RAND_BOOL()) {
		st->type = SOCK_SEQPACKET;
		st->protocol = DNPROTO_NSP;
	} else {
		st->type = SOCK_STREAM;
		st->protocol = rnd() % PROTO_MAX;
	}
}

static const unsigned int decnet_opts[] = {
	SO_CONDATA, SO_CONACCESS, SO_PROXYUSR, SO_LINKINFO,
	DSO_CONDATA, DSO_DISDATA, DSO_CONACCESS, DSO_ACCEPTMODE,
	DSO_CONACCEPT, DSO_CONREJECT, DSO_LINKINFO, DSO_STREAM,
	DSO_SEQPACKET, DSO_MAXWINDOW, DSO_NODELAY, DSO_CORK,
	DSO_SERVICES, DSO_INFO
};

static void decnet_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_DECNET;
	so->optname = RAND_ARRAY(decnet_opts);

	// TODO: set optlen correctly
}

struct netproto proto_decnet = {
	.name = "decnet",
	.socket = decnet_rand_socket,
	.setsockopt = decnet_setsockopt,
	.gen_sockaddr = decnet_gen_sockaddr,
};
