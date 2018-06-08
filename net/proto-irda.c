#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h> /* old irda.h is broken */
#include <sys/un.h>
/* old irda.h does not include something which defines sa_family_t */
#include <netinet/in.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

#ifdef USE_IRDA
#include <linux/irda.h>

static void irda_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_irda *irda;
	unsigned int i;

	irda = zmalloc(sizeof(struct sockaddr_irda));

	irda->sir_family = PF_IRDA;
	irda->sir_lsap_sel = rnd();
	irda->sir_addr = rnd();
	for (i = 0; i < 25; i++)
		irda->sir_name[i] = rnd();
	*addr = (struct sockaddr *) irda;
	*addrlen = sizeof(struct sockaddr_irda);
}

static const unsigned int irda_opts[] = {
	IRLMP_ENUMDEVICES, IRLMP_IAS_SET, IRLMP_IAS_QUERY, IRLMP_HINTS_SET,
	IRLMP_QOS_SET, IRLMP_QOS_GET, IRLMP_MAX_SDU_SIZE, IRLMP_IAS_GET,
	IRLMP_IAS_DEL, IRLMP_HINT_MASK_SET, IRLMP_WAITDEVICE
};

static void irda_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_IRDA;
	so->optname = RAND_ARRAY(irda_opts);
}

static struct socket_triplet irda_triplets[] = {
	{ .family = PF_IRDA, .protocol = IRDAPROTO_UNITDATA, .type = SOCK_DGRAM },
	{ .family = PF_IRDA, .protocol = IRDAPROTO_ULTRA, .type = SOCK_DGRAM },
	{ .family = PF_IRDA, .protocol = 0, .type = SOCK_SEQPACKET },
	{ .family = PF_IRDA, .protocol = 0, .type = SOCK_STREAM },
};

const struct netproto proto_irda = {
	.name = "irda",
	.setsockopt = irda_setsockopt,
	.gen_sockaddr = irda_gen_sockaddr,
	.valid_triplets = irda_triplets,
	.nr_triplets = ARRAY_SIZE(irda_triplets),
};

#endif
