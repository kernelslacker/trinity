#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"

void packet_gen_sockaddr(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_pkt *pkt;
	unsigned int i;

	//TODO: See also sockaddr_ll
	pkt = malloc(sizeof(struct sockaddr_pkt));
	if (pkt == NULL)
		return;

	pkt->spkt_family = PF_PACKET;
	for (i = 0; i < 14; i++)
		pkt->spkt_device[i] = rand();
	*addr = (unsigned long) pkt;
	*addrlen = sizeof(struct sockaddr_pkt);
}

void packet_rand_socket(struct proto_type *pt)
{
	pt->protocol = htons(ETH_P_ALL);

	if (rand() % 8 == 0) {
		pt->protocol = rand();
		if (rand_bool())
			pt->protocol = (uint16_t) rand();
	}

	switch (rand() % 3) {
	case 0: pt->type = SOCK_DGRAM;
		break;
	case 1: pt->type = SOCK_RAW;
		break;
	case 2: pt->type = SOCK_PACKET;
		break;
	default: break;
	}
}
