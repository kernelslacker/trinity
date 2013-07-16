#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/irda.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"

void gen_irda(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_irda *irda;
	unsigned int i;

	irda = malloc(sizeof(struct sockaddr_irda));
	if (irda == NULL)
		return;

	irda->sir_family = PF_IRDA;
	irda->sir_lsap_sel = rand();
	irda->sir_addr = rand();
	for (i = 0; i < 25; i++)
		irda->sir_name[i] = rand();
	*addr = (unsigned long) irda;
	*addrlen = sizeof(struct sockaddr_irda);
}

void irda_rand_socket(struct proto_type *pt)
{
	switch (rand() % 3) {

	case 0: pt->type = SOCK_STREAM;
		pt->protocol = rand() % PROTO_MAX;
		break;

	case 1: pt->type = SOCK_SEQPACKET;
		pt->protocol = rand() % PROTO_MAX;
		break;

	case 2: pt->type = SOCK_DGRAM;
		if (rand_bool())
			pt->protocol = IRDAPROTO_ULTRA;
		else
			pt->protocol = IRDAPROTO_UNITDATA;
		break;

	default:break;
	}
}
