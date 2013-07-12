#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <stdlib.h>
#include "net.h"

void gen_packet(unsigned long *addr, unsigned long *addrlen)
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
