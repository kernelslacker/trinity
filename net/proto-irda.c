#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h> /* old irda.h is broken */
#include <sys/un.h>
/* old irda.h does not include something which defines sa_family_t */
#include <netinet/in.h>
#include <linux/irda.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

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

static void irda_rand_socket(struct socket_triplet *st)
{
	switch (rnd() % 3) {

	case 0: st->type = SOCK_STREAM;
		st->protocol = rnd() % PROTO_MAX;
		break;

	case 1: st->type = SOCK_SEQPACKET;
		st->protocol = rnd() % PROTO_MAX;
		break;

	case 2: st->type = SOCK_DGRAM;
		if (RAND_BOOL())
			st->protocol = IRDAPROTO_ULTRA;
		else
			st->protocol = IRDAPROTO_UNITDATA;
		break;

	default:break;
	}
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

static void gen_irda(void)
{
	generate_socket(PF_IRDA, IRDAPROTO_UNITDATA, SOCK_DGRAM);
	generate_socket(PF_IRDA, IRDAPROTO_ULTRA, SOCK_DGRAM);
	generate_socket(PF_IRDA, 0, SOCK_SEQPACKET);
	generate_socket(PF_IRDA, 0, SOCK_STREAM);
}

const struct netproto proto_irda = {
	.name = "irda",
	.socket = irda_rand_socket,
	.setsockopt = irda_setsockopt,
	.gen_sockaddr = irda_gen_sockaddr,
	.generate = gen_irda,
};
