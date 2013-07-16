#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/llc.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"

void gen_llc(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_llc *llc;
	unsigned int i;

	llc = malloc(sizeof(struct sockaddr_llc));
	if (llc == NULL)
		return;
	llc->sllc_family = AF_LLC;
	llc->sllc_arphrd = ARPHRD_ETHER;
	llc->sllc_test = rand();
	llc->sllc_xid = rand();
	llc->sllc_ua = rand();
	llc->sllc_sap = rand();
	for (i = 0; i < IFHWADDRLEN; i++)
		llc->sllc_mac[i] = rand();
	*addr = (unsigned long) llc;
	*addrlen = sizeof(struct sockaddr_llc);
}

void llc_rand_socket(struct proto_type *pt)
{
	pt->protocol = rand() % PROTO_MAX;
	if (rand_bool())
		pt->type = SOCK_STREAM;
	else
		pt->type = SOCK_DGRAM;
}
