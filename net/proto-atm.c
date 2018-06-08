#include <stdlib.h>
#include <linux/atmdev.h>
#include <linux/atm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

static void atmpvc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_atmpvc *atmpvc;

	atmpvc = zmalloc(sizeof(struct sockaddr_atmpvc));

	atmpvc->sap_family = PF_ATMPVC;
	atmpvc->sap_addr.itf = rnd();
	atmpvc->sap_addr.vpi = rnd();
	atmpvc->sap_addr.vci = rnd();
	*addr = (struct sockaddr *) atmpvc;
	*addrlen = sizeof(struct sockaddr_atmpvc);
}

static void atmsvc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_atmsvc *atmsvc;
	unsigned int i;

	atmsvc = zmalloc(sizeof(struct sockaddr_atmsvc));

	atmsvc->sas_family = PF_ATMSVC;
	for (i = 0; i < ATM_ESA_LEN; i++)
		atmsvc->sas_addr.prv[i] = rnd();
	for (i = 0; i < ATM_E164_LEN; i++)
		atmsvc->sas_addr.pub[i] = rnd();
	atmsvc->sas_addr.lij_type = rnd();
	atmsvc->sas_addr.lij_id = rnd();
	*addr = (struct sockaddr *) atmsvc;
	*addrlen = sizeof(struct sockaddr_atmsvc);
}

// TODO: If anyone gives a crap about ATM, we could do better
// here and separate the pvc and svc ops.
// Personally, I couldn't care less, so throw everything in the same array
// just to make this simpler.
static const unsigned int atm_opts[] = {
	SO_SETCLP, SO_CIRANGE, SO_ATMQOS, SO_ATMSAP, SO_ATMPVC, SO_MULTIPOINT,
};

static void atm_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_ATM;
	so->optname = RAND_ARRAY(atm_opts);
}

static struct socket_triplet atmpvc_triplet[] = {
	{ .family = PF_ATMPVC, .protocol = 0, .type = SOCK_DGRAM },
};

static struct socket_triplet atmsvc_triplet[] = {
	{ .family = PF_ATMSVC, .protocol = 0, .type = SOCK_DGRAM },
};


const struct netproto proto_atmpvc = {
	.name = "atmpvc",
//	.socket = atm_rand_socket,
	.setsockopt = atm_setsockopt,
	.gen_sockaddr = atmpvc_gen_sockaddr,
	.valid_triplets = atmpvc_triplet,
	.nr_triplets = ARRAY_SIZE(atmpvc_triplet),
};
const struct netproto proto_atmsvc = {
	.name = "atmsvc",
//	.socket = atm_rand_socket,
	.setsockopt = atm_setsockopt,
	.gen_sockaddr = atmsvc_gen_sockaddr,
	.valid_triplets = atmsvc_triplet,
	.nr_triplets = ARRAY_SIZE(atmsvc_triplet),
};
