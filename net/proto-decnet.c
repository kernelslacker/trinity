#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/dn.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// ARRAY_SIZE
#include "compat.h"

void decnet_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_dn *dn;
	unsigned int i;

	dn = zmalloc(sizeof(struct sockaddr_dn));

	dn->sdn_family = PF_DECnet;
	dn->sdn_flags = rand();
	dn->sdn_objnum = rand();
	dn->sdn_objnamel = rand() % 16;
	for (i = 0; i < dn->sdn_objnamel; i++)
		dn->sdn_objname[i] = rand();
	dn->sdn_add.a_len = rand() % 2;
	dn->sdn_add.a_addr[0] = rand();
	dn->sdn_add.a_addr[1] = rand();
	*addr = (struct sockaddr *) dn;
	*addrlen = sizeof(struct sockaddr_dn);
}

void decnet_rand_socket(struct socket_triplet *st)
{
	if (rand_bool()) {
		st->type = SOCK_SEQPACKET;
		st->protocol = DNPROTO_NSP;
	} else {
		st->type = SOCK_STREAM;
		st->protocol = rand() % PROTO_MAX;
	}
}

#define NR_SOL_DECNET_OPTS ARRAY_SIZE(decnet_opts)
static const unsigned int decnet_opts[] = {
	SO_CONDATA, SO_CONACCESS, SO_PROXYUSR, SO_LINKINFO,
	DSO_CONDATA, DSO_DISDATA, DSO_CONACCESS, DSO_ACCEPTMODE,
	DSO_CONACCEPT, DSO_CONREJECT, DSO_LINKINFO, DSO_STREAM,
	DSO_SEQPACKET, DSO_MAXWINDOW, DSO_NODELAY, DSO_CORK,
	DSO_SERVICES, DSO_INFO
};

void decnet_setsockopt(struct sockopt *so)
{
	unsigned char val;

	so->level = SOL_DECNET;

	val = rand() % NR_SOL_DECNET_OPTS;
	so->optname = decnet_opts[val];

	// TODO: set optlen correctly

}
