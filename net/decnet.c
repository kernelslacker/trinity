#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/dn.h>
#include <stdlib.h>

void gen_decnet(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_dn *dn;
	unsigned int i;

	dn = malloc(sizeof(struct sockaddr_dn));
	if (dn == NULL)
		return;

	dn->sdn_family = PF_DECnet;
	dn->sdn_flags = rand();
	dn->sdn_objnum = rand();
	dn->sdn_objnamel = rand() % 16;
	for (i = 0; i < dn->sdn_objnamel; i++)
		dn->sdn_objname[i] = rand();
	dn->sdn_add.a_len = rand() % 2;
	dn->sdn_add.a_addr[0] = rand();
	dn->sdn_add.a_addr[1] = rand();
	*addr = (unsigned long) dn;
	*addrlen = sizeof(struct sockaddr_dn);
}
