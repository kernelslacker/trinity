#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/phonet.h>
#include <stdlib.h>

void gen_phonet(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_pn *pn;

	pn = malloc(sizeof(struct sockaddr_pn));
	if (pn == NULL)
		return;

	pn->spn_family = PF_PHONET;
	pn->spn_obj = rand();
	pn->spn_dev = rand();
	pn->spn_resource = rand();
	*addr = (unsigned long) pn;
	*addrlen = sizeof(struct sockaddr_pn);
}
