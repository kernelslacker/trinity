#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/ax25.h>
#include <stdlib.h>
#include "maps.h"	// page_rand

void gen_ax25(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_ax25 *ax25;

	ax25 = malloc(sizeof(struct sockaddr_ax25));
	if (ax25 == NULL)
		return;

	ax25->sax25_family = PF_AX25;
	strncpy(ax25->sax25_call.ax25_call, page_rand, 7);
	ax25->sax25_ndigis = rand();
	*addr = (unsigned long) ax25;
	*addrlen = sizeof(struct sockaddr_ax25);
}
