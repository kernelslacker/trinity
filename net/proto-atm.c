#include <linux/atmdev.h>
#include <linux/atm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "net.h"
#include "random.h"
#include "compat.h"
#include "rnd.h"

static void atmpvc_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_atmpvc *atmpvc;

	atmpvc = zmalloc_tracked(sizeof(struct sockaddr_atmpvc));

	atmpvc->sap_family = PF_ATMPVC;
	atmpvc->sap_addr.itf = rnd_u32();
	atmpvc->sap_addr.vpi = rnd_u32();
	atmpvc->sap_addr.vci = rnd_u32();
	*addr = (struct sockaddr *) atmpvc;
	*addrlen = sizeof(struct sockaddr_atmpvc);
}

static void atmsvc_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_atmsvc *atmsvc;
	unsigned int i;

	atmsvc = zmalloc_tracked(sizeof(struct sockaddr_atmsvc));

	atmsvc->sas_family = PF_ATMSVC;
	for (i = 0; i < ATM_ESA_LEN; i++)
		atmsvc->sas_addr.prv[i] = rnd_u32();
	for (i = 0; i < ATM_E164_LEN; i++)
		atmsvc->sas_addr.pub[i] = rnd_u32();
	atmsvc->sas_addr.lij_type = rnd_u32();
	atmsvc->sas_addr.lij_id = rnd_u32();
	*addr = (struct sockaddr *) atmsvc;
	*addrlen = sizeof(struct sockaddr_atmsvc);
}

/* Options valid on PVC sockets. */
static const unsigned int atmpvc_opts[] = {
	SO_SETCLP, SO_ATMQOS, SO_ATMSAP, SO_ATMPVC, SO_MULTIPOINT,
};

/* Options valid on SVC sockets. */
static const unsigned int atmsvc_opts[] = {
	SO_SETCLP, SO_CIRANGE, SO_ATMQOS, SO_ATMSAP, SO_MULTIPOINT,
};

/*
 * vcc_setsockopt (net/atm/common.c) length-rejects the struct-shaped
 * optnames with EINVAL when optlen < sizeof(the expected struct), so a
 * blanket sizeof(unsigned int) never reaches the per-option handler.
 * Size optlen per-optname; the zero-filled optval page already passes
 * copy_from_user, length is the killer.
 */
static size_t atm_optlen_for(unsigned int optname)
{
	switch (optname) {
	case SO_ATMQOS:
		return sizeof(struct atm_qos);
	case SO_ATMSAP:
		return sizeof(struct atm_sap);
	case SO_CIRANGE:
		return sizeof(struct atm_cirange);
	default:
		return sizeof(unsigned int);
	}
}

static void atmpvc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_ATM;
	so->optname = RAND_ARRAY(atmpvc_opts);
	so->optlen = atm_optlen_for(so->optname);
}

static void atmsvc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_ATM;
	so->optname = RAND_ARRAY(atmsvc_opts);
	so->optlen = atm_optlen_for(so->optname);
}

static struct socket_triplet atmpvc_triplet[] = {
	{ .family = PF_ATMPVC, .protocol = 0, .type = SOCK_DGRAM },
};

static struct socket_triplet atmsvc_triplet[] = {
	{ .family = PF_ATMSVC, .protocol = 0, .type = SOCK_DGRAM },
};


const struct netproto proto_atmpvc = {
	.name = "atmpvc",
	.setsockopt = atmpvc_setsockopt,
	.gen_sockaddr = atmpvc_gen_sockaddr,
	.valid_triplets = atmpvc_triplet,
	.nr_triplets = ARRAY_SIZE(atmpvc_triplet),
};
const struct netproto proto_atmsvc = {
	.name = "atmsvc",
	.setsockopt = atmsvc_setsockopt,
	.gen_sockaddr = atmsvc_gen_sockaddr,
	.valid_triplets = atmsvc_triplet,
	.nr_triplets = ARRAY_SIZE(atmsvc_triplet),
};
