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
#include "utils.h"	// ARRAY_SIZE
#include "compat.h"

void irda_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_irda *irda;
	unsigned int i;

	irda = zmalloc(sizeof(struct sockaddr_irda));

	irda->sir_family = PF_IRDA;
	irda->sir_lsap_sel = rand();
	irda->sir_addr = rand();
	for (i = 0; i < 25; i++)
		irda->sir_name[i] = rand();
	*addr = (struct sockaddr *) irda;
	*addrlen = sizeof(struct sockaddr_irda);
}

void irda_rand_socket(struct socket_triplet *st)
{
	switch (rand() % 3) {

	case 0: st->type = SOCK_STREAM;
		st->protocol = rand() % PROTO_MAX;
		break;

	case 1: st->type = SOCK_SEQPACKET;
		st->protocol = rand() % PROTO_MAX;
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

#define NR_SOL_IRDA_OPTS ARRAY_SIZE(irda_opts)
static const unsigned int irda_opts[] = {
	IRLMP_ENUMDEVICES, IRLMP_IAS_SET, IRLMP_IAS_QUERY, IRLMP_HINTS_SET,
	IRLMP_QOS_SET, IRLMP_QOS_GET, IRLMP_MAX_SDU_SIZE, IRLMP_IAS_GET,
	IRLMP_IAS_DEL, IRLMP_HINT_MASK_SET, IRLMP_WAITDEVICE };

void irda_setsockopt(struct sockopt *so)
{
	unsigned char val;

	val = rand() % NR_SOL_IRDA_OPTS;
	so->optname = irda_opts[val];
}
